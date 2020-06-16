import contextlib
import json
import logging.config
import os
import sys
import tarfile
import time
from tempfile import TemporaryFile

import docker
from kubernetes import client
from kubernetes import config
from kubernetes.stream import stream
from ldap3 import Connection
from ldap3 import Server
from ldap3 import BASE
from ldap3 import MODIFY_REPLACE

from pygluu.containerlib.persistence.couchbase import CouchbaseClient
from pygluu.containerlib.persistence.couchbase import get_couchbase_user
from pygluu.containerlib.persistence.couchbase import get_couchbase_password
from pygluu.containerlib.utils import decode_text
from pygluu.containerlib.utils import encode_text
from pygluu.containerlib.utils import exec_cmd
from pygluu.containerlib.utils import generate_base64_contents

from base_patcher import BasePatcher
from settings import LOGGING_CONFIG

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("certman")

SIG_KEYS = "RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512 RSA1_5 RSA-OAEP"
ENC_KEYS = SIG_KEYS


def merge_keys(new_keys, old_keys):
    """Merges new and old keys while omitting expired key.
    """
    now = int(time.time() * 1000)
    for key in old_keys["keys"]:
        if key.get("exp") > now:
            new_keys["keys"].append(key)
    return new_keys


def encode_jks(manager, jks="/etc/certs/oxauth-keys.jks"):
    encoded_jks = ""
    with open(jks, "rb") as fd:
        encoded_jks = encode_text(fd.read(), manager.secret.get("encoded_salt"))
    return encoded_jks


def generate_openid_keys(passwd, jks_path, dn, exp=365):
    if os.path.isfile(jks_path):
        os.unlink(jks_path)

    cmd = (
        "java -Dlog4j.defaultInitOverride=true "
        "-jar /app/javalibs/oxauth-client.jar "
        f"-enc_keys {ENC_KEYS} -sig_keys {SIG_KEYS} "
        f"-dnname '{dn}' -expiration_hours {exp} "
        f"-keystore {jks_path} -keypasswd {passwd}"
    )
    return exec_cmd(cmd)


class BasePersistence(object):
    def get_oxauth_config(self):
        raise NotImplementedError

    def modify_oxauth_config(self, id_, ox_rev, conf_dynamic, conf_webkeys):
        raise NotImplementedError


class LdapPersistence(BasePersistence):
    def __init__(self, host, user, password):
        ldap_server = Server(host, port=1636, use_ssl=True)
        self.backend = Connection(ldap_server, user, password)

    def get_oxauth_config(self):
        # base DN for oxAuth config
        oxauth_base = ",".join([
            "ou=oxauth",
            "ou=configuration",
            "o=gluu",
        ])

        with self.backend as conn:
            conn.search(
                search_base=oxauth_base,
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=[
                    "oxRevision",
                    "oxAuthConfWebKeys",
                    "oxAuthConfDynamic",
                ]
            )

            if not conn.entries:
                return {}

            entry = conn.entries[0]

            config = {
                "id": entry.entry_dn,
                "oxRevision": entry["oxRevision"][0],
                "oxAuthConfWebKeys": entry["oxAuthConfWebKeys"][0],
                "oxAuthConfDynamic": entry["oxAuthConfDynamic"][0],
            }
            return config

    def modify_oxauth_config(self, id_, ox_rev, conf_dynamic, conf_webkeys):
        with self.backend as conn:
            conn.modify(id_, {
                'oxRevision': [(MODIFY_REPLACE, [str(ox_rev)])],
                'oxAuthConfWebKeys': [(MODIFY_REPLACE, [json.dumps(conf_webkeys)])],
                'oxAuthConfDynamic': [(MODIFY_REPLACE, [json.dumps(conf_dynamic)])],
            })

            result = conn.result["description"]
            return result == "success"


class CouchbasePersistence(BasePersistence):
    def __init__(self, host, user, password):
        self.backend = CouchbaseClient(host, user, password)

    def get_oxauth_config(self):
        req = self.backend.exec_query(
            "SELECT oxRevision, oxAuthConfDynamic, oxAuthConfWebKeys "
            "FROM `gluu` "
            "USE KEYS 'configuration_oxauth'",
        )
        if not req.ok:
            return {}

        config = req.json()["results"][0]

        if not config:
            return {}

        config.update({"id": "configuration_oxauth"})
        return config

    def modify_oxauth_config(self, id_, ox_rev, conf_dynamic, conf_webkeys):
        conf_dynamic = json.dumps(conf_dynamic)
        conf_webkeys = json.dumps(conf_webkeys)

        req = self.backend.exec_query(
            f"UPDATE `gluu` USE KEYS '{id_}' "
            f"SET oxRevision={ox_rev}, oxAuthConfDynamic={conf_dynamic}, "
            f"oxAuthConfWebKeys={conf_webkeys} "
            "RETURNING oxRevision"
        )

        if not req.ok:
            return False
        return True


class BaseClient(object):
    def get_oxauth_containers(self):
        """Gets oxAuth containers.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError

    def get_container_ip(self, container):
        """Gets container's IP address.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError

    def get_container_name(self, container):
        """Gets container's IP name.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError

    def copy_to_container(self, container, path):
        """Copy path to container.

        Subclass __MUST__ implement this method.
        """
        raise NotImplementedError

    def exec_cmd(self, container, cmd):
        raise NotImplementedError


class DockerClient(BaseClient):
    def __init__(self, base_url="unix://var/run/docker.sock"):
        self.client = docker.DockerClient(base_url=base_url)

    def get_oxauth_containers(self):
        return self.client.containers.list(filters={'label': 'APP_NAME=oxauth'})

    def get_container_ip(self, container):
        for _, network in container.attrs["NetworkSettings"]["Networks"].items():
            return network["IPAddress"]

    def get_container_name(self, container):
        return container.name

    def copy_to_container(self, container, path):
        src = os.path.basename(path)
        dirname = os.path.dirname(path)

        os.chdir(dirname)

        with tarfile.open(src + ".tar", "w:gz") as tar:
            tar.add(src)

        with open(src + ".tar", "rb") as f:
            payload = f.read()

            # create directory first
            container.exec_run("mkdir -p {}".format(dirname))

            # copy file
            container.put_archive(os.path.dirname(path), payload)

        with contextlib.suppress(FileNotFoundError):
            os.unlink(src + ".tar")

    def exec_cmd(self, container, cmd):
        container.exec_run(cmd)


class KubernetesClient(BaseClient):
    def __init__(self):
        config_loaded = False

        try:
            config.load_incluster_config()
            config_loaded = True
        except config.config_exception.ConfigException:
            logger.warn("Unable to load in-cluster configuration; trying to load from Kube config file")
            try:
                config.load_kube_config()
                config_loaded = True
            except (IOError, config.config_exception.ConfigException) as exc:
                logger.warn("Unable to load Kube config; reason={}".format(exc))

        if not config_loaded:
            logger.error("Unable to load in-cluster or Kube config")
            sys.exit(1)

        cli = client.CoreV1Api()
        cli.api_client.configuration.assert_hostname = False
        self.client = cli

    def get_oxauth_containers(self):
        return self.client.list_pod_for_all_namespaces(
            label_selector='APP_NAME=oxauth'
        ).items

    def get_container_ip(self, container):
        return container.status.pod_ip

    def get_container_name(self, container):
        return container.metadata.name

    def copy_to_container(self, container, path):
        # make sure parent directory is created first
        resp = stream(
            self.client.connect_get_namespaced_pod_exec,
            container.metadata.name,
            container.metadata.namespace,
            # command=["/bin/sh", "-c", "mkdir -p {}".format(os.path.dirname(path))],
            command=["mkdir -p {}".format(os.path.dirname(path))],
            stderr=True,
            stdin=True,
            stdout=True,
            tty=False,
        )

        # copy file implementation
        resp = stream(
            self.client.connect_get_namespaced_pod_exec,
            container.metadata.name,
            container.metadata.namespace,
            command=["tar", "xvf", "-", "-C", "/"],
            stderr=True,
            stdin=True,
            stdout=True,
            tty=False,
            _preload_content=False,
        )

        with TemporaryFile() as tar_buffer:
            with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
                tar.add(path)

            tar_buffer.seek(0)
            commands = []
            commands.append(tar_buffer.read())

            while resp.is_open():
                resp.update(timeout=1)
                if resp.peek_stdout():
                    # logger.info("STDOUT: %s" % resp.read_stdout())
                    pass
                if resp.peek_stderr():
                    # logger.info("STDERR: %s" % resp.read_stderr())
                    pass
                if commands:
                    c = commands.pop(0)
                    resp.write_stdin(c.decode())
                else:
                    break
            resp.close()

    def exec_cmd(self, container, cmd):
        stream(
            self.client.connect_get_namespaced_pod_exec,
            container.metadata.name,
            container.metadata.namespace,
            # command=["/bin/sh", "-c", cmd],
            command=[cmd],
            stderr=True,
            stdin=True,
            stdout=True,
            tty=False,
        )


class OxauthPatcher(BasePatcher):
    def __init__(self, manager, source, dry_run, **opts):
        super(OxauthPatcher, self).__init__(manager, source, dry_run, **opts)

        persistence_type = os.environ.get("GLUU_PERSISTENCE_TYPE", "ldap")
        ldap_mapping = os.environ.get("GLUU_PERSISTENCE_LDAP_MAPPING", "default")

        if persistence_type in ("ldap", "couchbase"):
            backend_type = persistence_type
        else:
            # persistence_type is hybrid
            if ldap_mapping == "default":
                backend_type = "ldap"
            else:
                backend_type = "couchbase"

        # resolve backend
        if backend_type == "ldap":
            host = os.environ.get("GLUU_LDAP_URL", "localhost:1636")
            user = manager.config.get("ldap_binddn")
            password = decode_text(
                manager.secret.get("encoded_ox_ldap_pw"),
                manager.secret.get("encoded_salt"),
            )
            backend_cls = LdapPersistence
        else:
            host = os.environ.get("GLUU_COUCHBASE_URL", "localhost")
            user = get_couchbase_user(manager)
            password = get_couchbase_password(manager)
            backend_cls = CouchbasePersistence

        self.backend = backend_cls(host, user, password)
        self.rotation_interval = opts.get("interval", 48)

        metadata = os.environ.get("GLUU_CONTAINER_METADATA", "docker")
        if metadata == "kubernetes":
            self.meta_client = KubernetesClient()
        else:
            self.meta_client = DockerClient()

    def patch(self):
        config = self.backend.get_oxauth_config()

        if not config:
            # search failed due to missing entry
            logger.warning("Unable to find oxAuth config")
            return

        jks_pass = self.manager.secret.get("oxauth_openid_jks_pass")
        jks_fn = self.manager.config.get("oxauth_openid_jks_fn")
        jwks_fn = "/etc/certs/oxauth-keys.json"
        jks_dn = r"{}".format(self.manager.config.get("default_openid_jks_dn_name"))

        ox_rev = int(config["oxRevision"])

        try:
            conf_dynamic = json.loads(config["oxAuthConfDynamic"])
        except TypeError:  # not string/buffer
            conf_dynamic = config["oxAuthConfDynamic"]

        if conf_dynamic["keyRegenerationEnabled"]:
            logger.warning("keyRegenerationEnabled config was set to true; "
                           "skipping proccess to avoid conflict with "
                           "builtin key rotation feature in oxAuth")
            return

        conf_dynamic.update({
            "keyRegenerationEnabled": False,  # always set to False
            "keyRegenerationInterval": int(self.rotation_interval),
            "webKeysStorage": "keystore",
            "keyStoreSecret": jks_pass,
        })

        # exp_hours = int(self.rotation_interval) + (conf_dynamic["idTokenLifetime"] / 3600)
        exp_hours = int(self.rotation_interval)

        logger.info("Generating /etc/certs/oxauth-keys.json and /etc/certs/oxauth-keys.jks")
        out, err, retcode = generate_openid_keys(jks_pass, jks_fn, jks_dn, exp=exp_hours)

        if retcode != 0 or err:
            logger.error(f"Unable to generate keys; reason={err.decode()}")
            return

        with open(jwks_fn, "w") as f:
            f.write(out.decode())

        if self.dry_run:
            return

        oxauth_containers = self.meta_client.get_oxauth_containers()
        if not oxauth_containers:
            logger.warning("Unable to find any oxAuth container; make sure "
                           "to deploy oxAuth and set APP_NAME=oxauth "
                           "label on container level")
            return

        for container in oxauth_containers:
            name = self.meta_client.get_container_name(container)

            logger.info(f"creating backup of {name}:/etc/certs/oxauth-keys.jks")
            self.meta_client.exec_cmd(container, "cp /etc/certs/oxauth-keys.jks /etc/certs/oxauth-keys.jks.backup")
            logger.info(f"creating new {name}:/etc/certs/oxauth-keys.jks")
            self.meta_client.copy_to_container(container, jks_fn)

            logger.info(f"creating backup of {name}:/etc/certs/oxauth-keys.json")
            self.meta_client.exec_cmd(container, "cp /etc/certs/oxauth-keys.json /etc/certs/oxauth-keys.json.backup")
            logger.info(f"creating new {name}:/etc/certs/oxauth-keys.json")
            self.meta_client.copy_to_container(container, jwks_fn)

        try:
            keys = json.loads(out)

            logger.info("modifying oxAuth configuration")
            ox_modified = self.backend.modify_oxauth_config(
                config["id"],
                ox_rev + 1,
                conf_dynamic,
                keys,
            )

            if not ox_modified:
                # restore jks and jwks
                logger.warning("failed to modify oxAuth configuration")
                for container in oxauth_containers:
                    name = self.meta_client.get_container_name(container)
                    logger.info(f"restoring backup of {name}:/etc/certs/oxauth-keys.jks")
                    self.meta_client.exec_cmd(container, "cp /etc/certs/oxauth-keys.jks.backup /etc/certs/oxauth-keys.jks")
                    logger.info(f"restoring backup of {name}:/etc/certs/oxauth-keys.json")
                    self.meta_client.exec_cmd(container, "cp /etc/certs/oxauth-keys.json.backup /etc/certs/oxauth-keys.json")
                return

            self.manager.secret.set("oxauth_jks_base64", encode_jks(self.manager))
            self.manager.config.set("oxauth_key_rotated_at", int(time.time()))
            self.manager.secret.set("oxauth_openid_jks_pass", jks_pass)
            # jwks
            self.manager.secret.set(
                "oxauth_openid_key_base64",
                generate_base64_contents(json.dumps(keys)),
            )
        except (TypeError, ValueError,) as exc:
            logger.warning(f"Unable to get public keys; reason={exc}")
