import logging.config
import os

from settings import FROM_FILES
from settings import LOGGING_CONFIG
from utils import generate_keystore
from utils import generate_ssl_certkey

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("certman")


class BasePatcher(object):
    def __init__(self, manager, source, dry_run, **opts):
        self.manager = manager
        self.source = source
        self.dry_run = dry_run
        self.opts = opts

    def _patch_keystore(self, prefix, hostname, passwd):
        keystore_fn = "/etc/certs/{}.jks".format(prefix)
        files_exist = os.path.isfile(keystore_fn)

        if self.source == FROM_FILES and not files_exist:
            logger.warning(f"Unable to find {keystore_fn} file")
            return ""

        elif self.source == FROM_FILES and files_exist:
            logger.info(f"Using existing {keystore_fn} file")
            return keystore_fn

        # probably self-generate
        logger.info(f"Generating new {keystore_fn} files")
        generate_keystore(prefix, hostname, passwd)
        return keystore_fn

    def _patch_cert_key(self, prefix, cert_passwd):
        cert_fn = "/etc/certs/{}.crt".format(prefix)
        key_fn = "/etc/certs/{}.key".format(prefix)
        files_exist = os.path.isfile(cert_fn) and os.path.isfile(key_fn)

        if self.source == FROM_FILES and not files_exist:
            logger.warning(f"Unable to find {cert_fn} and {key_fn} files")
            return "", ""

        if self.source == FROM_FILES and files_exist:
            logger.info(f"Using existing {cert_fn} and {key_fn} files")
            return cert_fn, key_fn

        # probably self-generate
        logger.info(f"Generating new {cert_fn} and {key_fn} files")
        generate_ssl_certkey(
            prefix,
            cert_passwd,
            self.manager.config.get("admin_email"),
            self.manager.config.get("hostname"),
            self.manager.config.get("orgName"),
            self.manager.config.get("country_code"),
            self.manager.config.get("state"),
            self.manager.config.get("city"),
        )
        return cert_fn, key_fn

    def patch(self):
        raise NotImplementedError
