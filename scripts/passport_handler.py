import base64
import json
import logging.config
import os
import sys

from pygluu.containerlib.persistence.couchbase import CouchbaseClient
from pygluu.containerlib.persistence.couchbase import get_couchbase_user
from pygluu.containerlib.persistence.couchbase import get_couchbase_password
from pygluu.containerlib.persistence.ldap import LdapClient
from pygluu.containerlib.persistence.sql import SQLClient
from pygluu.containerlib.persistence.spanner import SpannerClient

from base_handler import BaseHandler
from settings import LOGGING_CONFIG
from utils import generate_openid_keys
from utils import export_openid_keys

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("certmanager")


class BasePersistence:
    def modify_passport_rs_client(self, jwks):
        raise NotImplementedError

    def modify_passport_rp_client(self, jwks):
        raise NotImplementedError

    def modify_passport_rs_config(self, cert_alias):
        raise NotImplementedError


class LdapPersistence(BasePersistence):
    def __init__(self, manager):
        self.client = LdapClient(manager)
        self.manager = manager

    def _modify_passport_client(self, client_id, jwks: str) -> bool:
        # v4.x format
        id_ = f"inum={client_id},ou=clients,o=gluu"

        # v3.x format (backward-compat)
        inum_org = self.manager.config.get("inumOrg")
        if inum_org:
            id_ = f"inum={client_id},ou=clients,o={inum_org},o=gluu"

        modified, _ = self.client.modify(
            id_,
            {
                "oxAuthJwks": [(self.client.MODIFY_REPLACE, [jwks])],
            },
        )
        return modified

    def modify_passport_rs_client(self, jwks: str) -> bool:
        client_id = self.manager.config.get("passport_rs_client_id")
        return self._modify_passport_client(client_id, jwks)

    def modify_passport_rp_client(self, jwks: str) -> bool:
        client_id = self.manager.config.get("passport_rp_client_id")
        return self._modify_passport_client(client_id, jwks)

    def modify_passport_rs_config(self, cert_alias: str) -> bool:
        # v4.x format
        id_ = "ou=oxtrust,ou=configuration,o=gluu"

        # v3.x format (backward-compat)
        inum_appliance = self.manager.config.get("inumAppliance")
        if inum_appliance:
            id_ = f"ou=oxtrust,ou=configuration,inum={inum_appliance},ou=appliances,o=gluu"

        entry = self.client.get(
            id_,
            attributes=["oxRevision", "oxTrustConfApplication"])

        if not entry:
            return False

        conf = json.loads(entry["oxTrustConfApplication"][0])
        conf["passportUmaClientKeyId"] = cert_alias
        rev = int(entry["oxRevision"][0]) + 1

        modified, _ = self.client.modify(
            entry.entry_dn,
            {
                "oxRevision": [(self.client.MODIFY_REPLACE, [str(rev)])],
                "oxTrustConfApplication": [(self.client.MODIFY_REPLACE, [json.dumps(conf)])],
            },
        )
        return modified


class CouchbasePersistence(BasePersistence):
    def __init__(self, manager):
        host = os.environ.get("GLUU_COUCHBASE_URL", "localhost")
        user = get_couchbase_user(manager)
        password = get_couchbase_password(manager)
        self.client = CouchbaseClient(host, user, password)
        self.manager = manager

    def _modify_passport_client(self, client_id, jwks: str) -> bool:
        bucket_prefix = os.environ.get("GLUU_COUCHBASE_BUCKET_PREFIX", "gluu")

        id_ = f"clients_{client_id}"
        req = self.client.exec_query(
            f"UPDATE `{bucket_prefix}` USE KEYS '{id_}' "
            f"SET oxAuthJwks={jwks}"
        )
        return req.ok

    def modify_passport_rs_client(self, jwks: str) -> bool:
        client_id = self.manager.config.get("passport_rs_client_id")
        return self._modify_passport_client(client_id, jwks)

    def modify_passport_rp_client(self, jwks: str) -> bool:
        client_id = self.manager.config.get("passport_rp_client_id")
        return self._modify_passport_client(client_id, jwks)

    def modify_passport_rs_config(self, cert_alias):
        bucket_prefix = os.environ.get("GLUU_COUCHBASE_BUCKET_PREFIX", "gluu")

        id_ = "configuration_oxtrust"
        req = self.client.exec_query(
            "SELECT oxRevision, oxTrustConfApplication "
            f"FROM `{bucket_prefix}` "
            f"USE KEYS '{id_}'"
        )

        if not req.ok:
            return False

        entry = req.json()["results"][0]
        if not entry:
            return False

        try:
            conf = json.loads(entry["oxTrustConfApplication"])
        except TypeError:
            conf = entry["oxTrustConfApplication"]

        conf["passportUmaClientKeyId"] = cert_alias
        rev = int(entry["oxRevision"]) + 1

        req = self.client.exec_query(
            f"UPDATE `{bucket_prefix}` USE KEYS '{id_}' "
            f"SET oxRevision={rev}, oxTrustConfApplication={json.dumps(conf)}"
        )
        return req.ok


class SQLPersistence(BasePersistence):
    def __init__(self, manager):
        self.client = SQLClient()
        self.manager = manager

    def _modify_passport_client(self, client_id, jwks: str) -> bool:
        return self.client.update("oxAuthClient", client_id, {"oxAuthJwks": jwks})

    def modify_passport_rs_client(self, jwks: str) -> bool:
        client_id = self.manager.config.get("passport_rs_client_id")
        return self._modify_passport_client(client_id, jwks)

    def modify_passport_rp_client(self, jwks: str) -> bool:
        client_id = self.manager.config.get("passport_rp_client_id")
        return self._modify_passport_client(client_id, jwks)

    def modify_passport_rs_config(self, cert_alias):
        id_ = "oxtrust"
        table_name = "oxTrustConfiguration"

        entry = self.client.get(table_name, id_, ["oxRevision", "oxTrustConfApplication"])

        if not entry:
            return False

        conf = json.loads(entry["oxTrustConfApplication"])
        conf["passportUmaClientKeyId"] = cert_alias
        rev = int(entry["oxRevision"]) + 1

        modified = self.client.update(
            table_name,
            id_,
            {
                "oxRevision": rev,
                "oxTrustConfApplication": json.dumps(conf),
            },
        )
        return modified


class SpannerPersistence(SQLPersistence):
    def __init__(self, manager):
        self.client = SpannerClient()
        self.manager = manager


_backend_classes = {
    "ldap": LdapPersistence,
    "couchbase": CouchbasePersistence,
    "sql": SQLPersistence,
    "spanner": SpannerPersistence,
}


class PassportHandler(BaseHandler):
    def __init__(self, manager, dry_run, **opts):
        super().__init__(manager, dry_run, **opts)

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

    def patch_passport_rs(self):
        jks_fn = self.manager.config.get("passport_rs_client_jks_fn")
        jwks_fn = self.manager.config.get("passport_rs_client_jwks_fn")

        logger.info(f"Generating new {jks_fn} and {jwks_fn}")

        out, err, retcode = generate_openid_keys(
            self.manager.secret.get("passport_rs_client_jks_pass"),
            jks_fn,
            jwks_fn,
            self.manager.config.get("default_openid_jks_dn_name"),
            exp=365 * 24,
        )
        if retcode != 0:
            logger.error(f"Unable to generate Passport RS keys; reason={err.decode()}")
            sys.exit(1)

        cert_alg = self.manager.config.get("passport_rs_client_cert_alg")
        cert_alias = ""
        for key in json.loads(out)["keys"]:
            if key["alg"] == cert_alg:
                cert_alias = key["kid"]
                break

        if not self.dry_run:
            client_modified = self.backend.modify_passport_rs_client(out.decode())
            config_modified = self.backend.modify_passport_rs_config(cert_alias)

            if client_modified and config_modified:
                self.manager.secret.set("passport_rs_client_base64_jwks", base64.b64encode(out))
                self.manager.secret.from_file(
                    "passport_rs_jks_base64", jks_fn, encode=True, binary_mode=True,
                )
                self.manager.config.set("passport_rs_client_cert_alias", cert_alias)

    def patch_passport_rp(self):
        jks_pass = self.manager.secret.get("passport_rp_client_jks_pass")
        jks_fn = self.manager.config.get("passport_rp_client_jks_fn")
        jwks_fn = self.manager.config.get("passport_rp_client_jwks_fn")
        client_cert_fn = self.manager.config.get("passport_rp_client_cert_fn")

        logger.info(f"Generating new {jks_fn} and {jwks_fn}")

        out, err, code = generate_openid_keys(
            jks_pass,
            jks_fn,
            jwks_fn,
            self.manager.config.get("default_openid_jks_dn_name"),
            exp=365 * 24,
        )
        if code != 0:
            logger.error(f"Unable to generate Passport RP keys; reason={err.decode()}")
            sys.exit(1)

        cert_alg = self.manager.config.get("passport_rp_client_cert_alg")
        cert_alias = ""
        for key in json.loads(out)["keys"]:
            if key["alg"] == cert_alg:
                cert_alias = key["kid"]
                break

        _, err, retcode = export_openid_keys(
            jks_fn, jks_pass, cert_alias, client_cert_fn,
        )
        if retcode != 0:
            logger.error(f"Unable to generate Passport RP client cert; reason={err.decode()}")
            sys.exit(1)

        if not self.dry_run:
            client_modified = self.backend.modify_passport_rp_client(out.decode())

            if client_modified:
                self.manager.secret.set("passport_rp_client_base64_jwks", base64.b64encode(out))
                self.manager.secret.from_file(
                    "passport_rp_jks_base64", jks_fn, encode=True, binary_mode=True,
                )
                self.manager.config.set("passport_rp_client_cert_alias", cert_alias)
                self.manager.secret.from_file("passport_rp_client_cert_base64", client_cert_fn, encode=True)

    def patch_passport_sp(self):
        cert_fn, key_fn = self._patch_cert_key("passport-sp")

        if not self.dry_run:
            self.manager.secret.from_file("passport_sp_cert_base64", cert_fn, encode=True)
            self.manager.secret.from_file("passport_sp_key_base64", key_fn, encode=True)

    def patch(self):
        self.patch_passport_rp()
        self.patch_passport_rs()
        self.patch_passport_sp()
