import logging.config
import os

from pygluu.containerlib.utils import exec_cmd

from base_patcher import BasePatcher
from settings import FROM_FILES
from settings import LOGGING_CONFIG

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("certman")


class OxshibbolethPatcher(BasePatcher):
    @classmethod
    def gen_idp3_key(cls, storepass):
        cmd = (
            "java -classpath '/app/javalibs/*' "
            "net.shibboleth.utilities.java.support.security.BasicKeystoreKeyStrategyTool "
            "--storefile /etc/certs/sealer.jks "
            "--versionfile /etc/certs/sealer.kver "
            "--alias secret "
            f"--storepass {storepass}"
        )
        return exec_cmd(cmd)

    def _patch_shib_sealer(self, passwd):
        sealer_jks = "/etc/certs/sealer.jks"
        sealer_kver = "/etc/certs/sealer.kver"

        files_exist = os.path.isfile(sealer_jks) and os.path.isfile(sealer_kver)

        if self.source == FROM_FILES and not files_exist:
            logger.warning(
                f"Unable to find {sealer_jks} and {sealer_kver} files"
            )
            return "", ""

        elif self.source == FROM_FILES and files_exist:
            logger.info(f"Using existing {sealer_jks} and {sealer_kver} files")
            return sealer_jks, sealer_kver

        # probably self-generate
        logger.info(f"Generating new {sealer_jks} and {sealer_kver} files")
        self.gen_idp3_key(passwd)
        return sealer_jks, sealer_kver

    def patch(self):
        passwd = self.manager.secret.get("shibJksPass")

        # shibIDP
        cert_fn, key_fn = self._patch_cert_key("shibIDP", passwd)
        if not self.dry_run:
            if cert_fn:
                self.manager.secret.from_file(
                    "shibIDP_cert", cert_fn, encode=True,
                )
            if key_fn:
                self.manager.secret.from_file(
                    "shibIDP_cert", key_fn, encode=True,
                )

        keystore_fn = self._patch_keystore(
            "shibIDP", self.manager.config.get("hostname"), passwd,
        )
        if not self.dry_run:
            if keystore_fn:
                self.manager.secret.from_file(
                    "shibIDP_jks_base64",
                    keystore_fn,
                    encode=True,
                    binary_mode=True,
                )

        sealer_jks_fn, sealer_kver_fn = self._patch_shib_sealer(passwd)
        if not self.dry_run:
            if sealer_jks_fn:
                self.manager.secret.from_file(
                    "sealer_jks_base64",
                    sealer_jks_fn,
                    encode=True,
                    binary_mode=True,
                )
            if sealer_kver_fn:
                self.manager.secret.from_file(
                    "sealer_kver_base64", sealer_kver_fn, encode=True,
                )

        # IDP signing
        cert_fn, key_fn = self._patch_cert_key("idp-signing", passwd)
        if not self.dry_run:
            if cert_fn:
                self.manager.secret.from_file(
                    "idp3SigningCertificateText", cert_fn,
                )
            if key_fn:
                self.manager.secret.from_file("idp3SigningKeyText", key_fn)

        # IDP encryption
        cert_fn, key_fn = self._patch_cert_key("idp-encryption", passwd)
        if not self.dry_run:
            if cert_fn:
                self.manager.secret.from_file(
                    "idp3EncryptionCertificateText", cert_fn,
                )
            if key_fn:
                self.manager.secret.from_file("idp3EncryptionKeyText", key_fn)
