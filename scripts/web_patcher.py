from base_patcher import BasePatcher


class WebPatcher(BasePatcher):
    def patch(self):
        passwd = self.manager.secret.get("ssl_cert_pass")
        cert_fn, key_fn = self._patch_cert_key("gluu_https", passwd)

        if not self.dry_run:
            if cert_fn:
                self.manager.secret.from_file("ssl_cert", cert_fn)
            if key_fn:
                self.manager.secret.from_file("ssl_key", key_fn)
