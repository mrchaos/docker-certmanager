import json
import logging.config
import os
import sys
import time
from collections import Counter
from collections import deque

from pygluu.containerlib.persistence.couchbase import CouchbaseClient
from pygluu.containerlib.persistence.couchbase import get_couchbase_user
from pygluu.containerlib.persistence.couchbase import get_couchbase_password
from pygluu.containerlib.persistence.ldap import LdapClient
from pygluu.containerlib.persistence.sql import SQLClient
from pygluu.containerlib.persistence.spanner import SpannerClient
from pygluu.containerlib.utils import encode_text
from pygluu.containerlib.utils import exec_cmd
from pygluu.containerlib.utils import generate_base64_contents
from pygluu.containerlib.utils import as_boolean
from pygluu.containerlib.meta import DockerMeta
from pygluu.containerlib.meta import KubernetesMeta

from base_handler import BaseHandler
from settings import LOGGING_CONFIG

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("certmanager")

SIG_KEYS = "RS256 RS384 RS512 ES256 ES384 ES512 PS256 PS384 PS512"
ENC_KEYS = "RSA1_5 RSA-OAEP"
KEY_STRATEGIES = ("OLDER", "NEWER", "FIRST")


def key_expired(exp):
    now = int(time.time()) * 1000  # in milliseconds
    return now >= exp


def keytool_import_key(src_jks_fn, dest_jks_fn, alias, password):
    cmd = f"keytool -importkeystore -srckeystore {src_jks_fn} -srcstorepass {password} -srcalias {alias} -destkeystore {dest_jks_fn} -deststorepass {password} -destalias {alias}"
    return exec_cmd(cmd)


def keytool_delete_key(jks_fn, alias, password):
    cmd = f"keytool -delete -alias {alias} -keystore {jks_fn} -storepass {password}"
    return exec_cmd(cmd)


def encode_jks(manager, jks="/etc/certs/oxauth-keys.jks"):
    encoded_jks = ""
    with open(jks, "rb") as fd:
        encoded_jks = encode_text(fd.read(), manager.secret.get("encoded_salt"))
    return encoded_jks


def generate_openid_keys(passwd, jks_path, dn, exp=48, sig_keys=SIG_KEYS, enc_keys=ENC_KEYS):
    if os.path.isfile(jks_path):
        os.unlink(jks_path)

    cmd = (
        "java -Dlog4j.defaultInitOverride=true "
        "-jar /app/javalibs/oxauth-client.jar "
        f"-enc_keys {enc_keys} -sig_keys {sig_keys} "
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
    def __init__(self, manager):
        self.client = LdapClient(manager)

    def get_oxauth_config(self):
        entry = self.client.get(
            "ou=oxauth,ou=configuration,o=gluu",
            attributes=["oxRevision", "oxAuthConfWebKeys", "oxAuthConfDynamic"],
        )

        if not entry:
            return {}

        config = {
            "id": entry.entry_dn,
            "oxRevision": entry["oxRevision"][0],
            "oxAuthConfWebKeys": entry["oxAuthConfWebKeys"][0],
            "oxAuthConfDynamic": entry["oxAuthConfDynamic"][0],
        }
        return config

    def modify_oxauth_config(self, id_, ox_rev, conf_dynamic, conf_webkeys):
        modified, _ = self.client.modify(
            id_,
            {
                "oxRevision": [(self.client.MODIFY_REPLACE, [str(ox_rev)])],
                "oxAuthConfWebKeys": [(self.client.MODIFY_REPLACE, [json.dumps(conf_webkeys)])],
                "oxAuthConfDynamic": [(self.client.MODIFY_REPLACE, [json.dumps(conf_dynamic)])],
            }
        )
        return modified


class CouchbasePersistence(BasePersistence):
    def __init__(self, manager):
        host = os.environ.get("GLUU_COUCHBASE_URL", "localhost")
        user = get_couchbase_user(manager)
        password = get_couchbase_password(manager)
        self.client = CouchbaseClient(host, user, password)

    def get_oxauth_config(self):
        bucket_prefix = os.environ.get("GLUU_COUCHBASE_BUCKET_PREFIX", "gluu")
        req = self.client.exec_query(
            "SELECT oxRevision, oxAuthConfDynamic, oxAuthConfWebKeys "
            f"FROM `{bucket_prefix}` "
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
        bucket_prefix = os.environ.get("GLUU_COUCHBASE_BUCKET_PREFIX", "gluu")

        req = self.client.exec_query(
            f"UPDATE `{bucket_prefix}` USE KEYS '{id_}' "
            f"SET oxRevision={ox_rev}, oxAuthConfDynamic={conf_dynamic}, "
            f"oxAuthConfWebKeys={conf_webkeys} "
            "RETURNING oxRevision"
        )

        if not req.ok:
            return False
        return True


class SQLPersistence(BasePersistence):
    def __init__(self, manager):
        self.client = SQLClient(manager)

    def get_oxauth_config(self):
        config = self.client.get(
            "oxAuthConfiguration",
            "oxauth",
            ["oxRevision", "oxAuthConfWebKeys", "oxAuthConfDynamic"],
        )

        if not config:
            return {}

        config["id"] = "oxauth"
        return config

    def modify_oxauth_config(self, id_, ox_rev, conf_dynamic, conf_webkeys):
        updated = self.client.update(
            "oxAuthConfiguration",
            "oxauth",
            {
                "oxRevision": ox_rev,
                "oxAuthConfWebKeys": json.dumps(conf_webkeys),
                "oxAuthConfDynamic": json.dumps(conf_dynamic),
            }
        )
        return updated


class SpannerPersistence(SQLPersistence):
    def __init__(self, manager):
        self.client = SpannerClient(manager)


_backend_classes = {
    "ldap": LdapPersistence,
    "couchbase": CouchbasePersistence,
    "sql": SQLPersistence,
    "spanner": SpannerPersistence,
}


class OxauthHandler(BaseHandler):
    def __init__(self, manager, dry_run, **opts):
        super(OxauthHandler, self).__init__(manager, dry_run, **opts)

        persistence_type = os.environ.get("GLUU_PERSISTENCE_TYPE", "ldap")
        ldap_mapping = os.environ.get("GLUU_PERSISTENCE_LDAP_MAPPING", "default")

        if persistence_type in ("ldap", "couchbase", "sql", "spanner"):
            backend_type = persistence_type
        else:
            # persistence_type is hybrid
            if ldap_mapping == "default":
                backend_type = "ldap"
            else:
                backend_type = "couchbase"

        # resolve backend
        self.backend = _backend_classes[backend_type](manager)

        self.rotation_interval = opts.get("interval", 48)
        self.push_keys = as_boolean(opts.get("push-to-container", True))
        self.key_strategy = opts.get("key-strategy", "OLDER")
        self.privkey_push_delay = opts.get("privkey-push-delay", 0)
        self.privkey_push_strategy = opts.get("privkey-push-strategy", "OLDER")
        self.sig_keys = resolve_sig_keys(opts.get("sig-keys", SIG_KEYS))
        self.enc_keys = resolve_enc_keys(opts.get("enc-keys", ENC_KEYS))

        metadata = os.environ.get("GLUU_CONTAINER_METADATA", "docker")
        if metadata == "kubernetes":
            self.meta_client = KubernetesMeta()
        else:
            self.meta_client = DockerMeta()

    @property
    def allowed_key_algs(self):
        algs = self.sig_keys.split() + self.enc_keys.split()
        return algs

    def get_merged_keys(self, exp_hours):
        # get previous JWKS
        with open("/etc/certs/oxauth-keys.old.json") as f:
            old_jwks = json.loads(f.read()).get("keys", [])

        # get previous JKS
        old_jks_fn = "/etc/certs/oxauth-keys.old.jks"
        self.manager.secret.to_file("oxauth_jks_base64", old_jks_fn, decode=True, binary_mode=True)

        # generate new JWKS and JKS
        jks_pass = self.manager.secret.get("oxauth_openid_jks_pass")
        jks_dn = r"{}".format(self.manager.config.get("default_openid_jks_dn_name"))
        jks_fn = "/etc/certs/oxauth-keys.jks"
        jwks_fn = "/etc/certs/oxauth-keys.json"
        logger.info(f"Generating new {jwks_fn} and {jks_fn}")
        out, err, retcode = generate_openid_keys(
            jks_pass, jks_fn, jks_dn, exp=exp_hours, sig_keys=self.sig_keys, enc_keys=self.enc_keys,
        )

        if retcode != 0:
            logger.error(f"Unable to generate keys; reason={err.decode()}")
            return

        new_jwks = deque(json.loads(out).get("keys", []))

        logger.info("Merging keys from previous rotation (if any)")
        # make sure keys sorted by newer ``exp`` first, so the older one
        # won't be added to new JWKS
        old_jwks = sorted(old_jwks, key=lambda k: k["exp"], reverse=True)

        cnt = Counter(j["alg"] for j in new_jwks)

        for jwk in old_jwks:
            # exclude alg if it's not allowed
            if jwk["alg"] not in self.allowed_key_algs:
                continue

            # cannot have more than 2 keys for same algorithm in new JWKS
            if cnt[jwk["alg"]] > 1:
                continue

            # insert old key to new keys
            new_jwks.appendleft(jwk)
            cnt[jwk["alg"]] += 1

            # import key to new JKS
            keytool_import_key(old_jks_fn, jks_fn, jwk["kid"], jks_pass)

        # update new JWKS file
        with open(jwks_fn, "w") as f:
            data = {"keys": list(new_jwks)}
            f.write(json.dumps(data, indent=2))

        # finalizing
        return jwks_fn, jks_fn

    def patch(self):
        strategies = ", ".join(KEY_STRATEGIES)

        if self.key_strategy not in KEY_STRATEGIES:
            logger.error(f"Key strategy must be one of {strategies}")
            sys.exit(1)

        if self.privkey_push_strategy not in KEY_STRATEGIES:
            logger.error(f"Private key push strategy must be one of {strategies}")
            sys.exit(1)

        push_delay_invalid = False
        try:
            if int(self.privkey_push_delay) < 0:
                push_delay_invalid = True
        except ValueError:
            push_delay_invalid = True

        if push_delay_invalid:
            logger.error("Invalid integer value for private key push delay")
            sys.exit(1)

        config = self.backend.get_oxauth_config()

        if not config:
            # search failed due to missing entry
            logger.warning("Unable to find oxAuth config")
            return

        try:
            conf_dynamic = json.loads(config["oxAuthConfDynamic"])
        except TypeError:  # not string/buffer
            conf_dynamic = config["oxAuthConfDynamic"]

        if conf_dynamic["keyRegenerationEnabled"]:
            logger.warning("keyRegenerationEnabled config was set to true; "
                           "skipping proccess to avoid conflict with "
                           "builtin key rotation feature in oxAuth")
            return

        jks_pass = self.manager.secret.get("oxauth_openid_jks_pass")

        conf_dynamic.update({
            "keyRegenerationEnabled": False,  # always set to False
            "keyRegenerationInterval": int(self.rotation_interval),
            "webKeysStorage": "keystore",
            "keyStoreSecret": jks_pass,
            "keySelectionStrategy": self.key_strategy,
            "keyAlgsAllowedForGeneration": self.allowed_key_algs,
        })

        # get old JWKS from persistence
        try:
            web_keys = json.loads(config["oxAuthConfWebKeys"])
        except TypeError:
            web_keys = config["oxAuthConfWebKeys"]

        with open("/etc/certs/oxauth-keys.old.json", "w") as f:
            f.write(json.dumps(web_keys, indent=2))

        exp_hours = int(self.rotation_interval) + int(conf_dynamic["idTokenLifetime"] / 3600)

        jwks_fn, jks_fn = self.get_merged_keys(exp_hours)

        if self.dry_run:
            return

        oxauth_containers = []

        if self.push_keys:
            oxauth_containers = self.meta_client.get_containers("APP_NAME=oxauth")
            if not oxauth_containers:
                logger.warning(
                    "Unable to find any oxAuth container; make sure "
                    "to deploy oxAuth and set APP_NAME=oxauth "
                    "label on container level"
                )
                # exit immediately to avoid persistence/secrets being modified
                return

        for container in oxauth_containers:
            name = self.meta_client.get_container_name(container)

            logger.info(f"creating backup of {name}:{jwks_fn}")
            self.meta_client.exec_cmd(container, f"cp {jwks_fn} {jwks_fn}.backup")
            logger.info(f"creating new {name}:{jwks_fn}")
            self.meta_client.copy_to_container(container, jwks_fn)

            if int(self.privkey_push_delay) > 0:
                # delayed jks push
                continue

            logger.info(f"creating backup of {name}:{jks_fn}")
            self.meta_client.exec_cmd(container, f"cp {jks_fn} {jks_fn}.backup")
            logger.info(f"creating new {name}:{jks_fn}")
            self.meta_client.copy_to_container(container, jks_fn)

        try:
            with open(jwks_fn) as f:
                keys = json.loads(f.read())

            logger.info("modifying oxAuth configuration")
            logger.info(f"using keySelectionStrategy {self.key_strategy}")
            ox_rev = int(config["oxRevision"]) + 1
            ox_modified = self.backend.modify_oxauth_config(
                config["id"],
                ox_rev,
                conf_dynamic,
                keys,
            )

            if not ox_modified:
                # restore jks and jwks
                logger.warning("failed to modify oxAuth configuration")
                for container in oxauth_containers:
                    logger.info(f"restoring backup of {name}:{jwks_fn}")
                    self.meta_client.exec_cmd(container, f"cp {jwks_fn}.backup {jwks_fn}")

                    if int(self.privkey_push_delay) > 0:
                        # delayed jks revert
                        continue

                    name = self.meta_client.get_container_name(container)
                    logger.info(f"restoring backup of {name}:{jks_fn}")
                    self.meta_client.exec_cmd(container, f"cp {jks_fn}.backup {jks_fn}")
                return

            self.manager.secret.set("oxauth_jks_base64", encode_jks(self.manager))
            self.manager.config.set("oxauth_key_rotated_at", int(time.time()))
            self.manager.secret.set("oxauth_openid_jks_pass", jks_pass)
            self.manager.config.set("auth_sig_keys", self.sig_keys)
            self.manager.config.set("auth_enc_keys", self.enc_keys)
            # jwks
            self.manager.secret.set(
                "oxauth_openid_key_base64",
                generate_base64_contents(json.dumps(keys)),
            )

            # publish delayed jks
            if int(self.privkey_push_delay) > 0:
                logger.info(f"Waiting for private key push delay ({int(self.privkey_push_delay)} seconds) ...")
                time.sleep(int(self.privkey_push_delay))
                for container in oxauth_containers:
                    logger.info(f"creating new {name}:{jks_fn}")
                    self.meta_client.copy_to_container(container, jks_fn)

                # key selection is changed
                if self.privkey_push_strategy != self.key_strategy:
                    ox_rev = ox_rev + 1
                    conf_dynamic.update({
                        "keySelectionStrategy": self.privkey_push_strategy,
                    })

                    logger.info(f"using keySelectionStrategy {self.privkey_push_strategy}")

                    self.backend.modify_oxauth_config(
                        config["id"],
                        ox_rev,
                        conf_dynamic,
                        keys,
                    )
        except (TypeError, ValueError,) as exc:
            logger.warning(f"Unable to get public keys; reason={exc}")

    def prune(self):
        config = self.backend.get_oxauth_config()

        if not config:
            # search failed due to missing entry
            logger.warning("Unable to find oxAuth config")
            return

        try:
            conf_dynamic = json.loads(config["oxAuthConfDynamic"])
        except TypeError:  # not string/buffer
            conf_dynamic = config["oxAuthConfDynamic"]

        if conf_dynamic["keyRegenerationEnabled"]:
            logger.warning("keyRegenerationEnabled config was set to true; "
                           "skipping proccess to avoid conflict with "
                           "builtin key rotation feature in oxAuth")
            return

        jks_pass = self.manager.secret.get("oxauth_openid_jks_pass")

        conf_dynamic.update({
            "keyRegenerationEnabled": False,  # always set to False
            "webKeysStorage": "keystore",
            "keyStoreSecret": jks_pass,
            "keyAlgsAllowedForGeneration": self.allowed_key_algs,
        })

        # get old JWKS from persistence
        try:
            web_keys = json.loads(config["oxAuthConfWebKeys"])
        except TypeError:
            web_keys = config["oxAuthConfWebKeys"]

        logger.info("Cleaning up keys (if any)")

        jks_fn = "/etc/certs/oxauth-keys.jks"
        self.manager.secret.to_file("oxauth_jks_base64", jks_fn, decode=True, binary_mode=True)

        # non-pruned keys
        new_jwks = []

        # make sure keys sorted by newer ``exp`` first, so the older one
        # won't be added to new JWKS
        old_jwks = web_keys.get("keys", [])
        old_jwks = sorted(old_jwks, key=lambda k: k["exp"], reverse=True)

        cnt = Counter(j["alg"] for j in new_jwks)

        for jwk in old_jwks:
            # exclude alg if it's not allowed
            if jwk["alg"] not in self.allowed_key_algs:
                keytool_delete_key(jks_fn, jwk["kid"], jks_pass)
                continue

            # cannot have more than 1 key for same algorithm in new JWKS
            if cnt[jwk["alg"]]:
                keytool_delete_key(jks_fn, jwk["kid"], jks_pass)
                continue

            # preserve the key
            new_jwks.append(jwk)
            cnt[jwk["alg"]] += 1

        web_keys["keys"] = new_jwks

        jwks_fn = "/etc/certs/oxauth-keys.json"
        with open(jwks_fn, "w") as f:
            f.write(json.dumps(web_keys, indent=2))

        if self.dry_run:
            return

        oxauth_containers = []

        if self.push_keys:
            oxauth_containers = self.meta_client.get_containers("APP_NAME=oxauth")
            if not oxauth_containers:
                logger.warning(
                    "Unable to find any oxAuth container; make sure "
                    "to deploy oxAuth and set APP_NAME=oxauth "
                    "label on container level"
                )
                # exit immediately to avoid persistence/secrets being modified
                return

        for container in oxauth_containers:
            name = self.meta_client.get_container_name(container)

            logger.info(f"creating backup of {name}:{jks_fn}")
            self.meta_client.exec_cmd(container, f"cp {jks_fn} {jks_fn}.backup")
            logger.info(f"creating new {name}:{jks_fn}")
            self.meta_client.copy_to_container(container, jks_fn)

            logger.info(f"creating backup of {name}:{jwks_fn}")
            self.meta_client.exec_cmd(container, f"cp {jwks_fn} {jwks_fn}.backup")
            logger.info(f"creating new {name}:{jwks_fn}")
            self.meta_client.copy_to_container(container, jwks_fn)

        try:
            with open(jwks_fn) as f:
                keys = json.loads(f.read())

            logger.info("modifying oxAuth configuration")
            ox_rev = int(config["oxRevision"])
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
                    logger.info(f"restoring backup of {name}:{jks_fn}")
                    self.meta_client.exec_cmd(container, f"cp {jks_fn}.backup {jks_fn}")
                    logger.info(f"restoring backup of {name}:{jwks_fn}")
                    self.meta_client.exec_cmd(container, f"cp {jwks_fn}.backup {jwks_fn}")
                return

            self.manager.secret.set("oxauth_jks_base64", encode_jks(self.manager))
            self.manager.config.set("oxauth_key_rotated_at", int(time.time()))
            self.manager.secret.set("oxauth_openid_jks_pass", jks_pass)
            self.manager.config.set("auth_sig_keys", self.sig_keys)
            self.manager.config.set("auth_enc_keys", self.enc_keys)
            # jwks
            self.manager.secret.set(
                "oxauth_openid_key_base64",
                generate_base64_contents(json.dumps(keys)),
            )
        except (TypeError, ValueError,) as exc:
            logger.warning(f"Unable to get public keys; reason={exc}")


def resolve_sig_keys(keys: str) -> str:
    """
    Resolves signing keys.

    :param keys: Space-separated signing keys.
    :returns: Space-separated allowed signing keys.
    """

    default_sig_keys = SIG_KEYS.split()
    sig_keys = []

    for k in keys.split():
        k = k.strip()

        if k not in default_sig_keys:
            continue
        sig_keys.append(k)

    if not sig_keys:
        sig_keys = default_sig_keys
        logger.warning(f"Signing keys are empty; fallback to default {SIG_KEYS}")
    return " ".join(sig_keys)


def resolve_enc_keys(keys: str) -> str:
    """
    Resolves encryption keys.

    :param keys: Space-separated encryption keys.
    :returns: Space-separated allowed encryption keys.
    """

    default_enc_keys = ENC_KEYS.split()
    enc_keys = []

    for k in keys.split():
        k = k.strip()

        if k not in default_enc_keys:
            continue
        enc_keys.append(k)

    if not enc_keys:
        enc_keys = default_enc_keys
        logger.warning(f"Encryption keys are empty; fallback to default {ENC_KEYS}")
    return " ".join(enc_keys)
