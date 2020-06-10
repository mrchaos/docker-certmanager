from pygluu.containerlib.utils import exec_cmd


def generate_ssl_certkey(suffix, passwd, email, hostname, org_name,
                         country_code, state, city):
    # create key with password
    _, err, retcode = exec_cmd(
        f"openssl genrsa -des3 -out /etc/certs/{suffix}.key.orig "
        f"-passout pass:'{passwd}' 2048"
    )
    assert retcode == 0, \
        f"Failed to generate SSL key with password; reason={err.decode()}"

    # create .key
    _, err, retcode = exec_cmd(
        f"openssl rsa -in /etc/certs/{suffix}.key.orig -passin pass:'{passwd}' "
        f"-out /etc/certs/{suffix}.key"
    )
    assert retcode == 0, f"Failed to generate SSL key; reason={err.decode()}"

    # create .csr
    _, err, retcode = exec_cmd(
        f"openssl req -new -key /etc/certs/{suffix}.key "
        f"-out /etc/certs/{suffix}.csr "
        f"-subj /C='{country_code}'/ST='{state}'/L='{city}'/O='{org_name}'"
        f"/CN='{hostname}'/emailAddress='{email}'"
    )
    assert retcode == 0, f"Failed to generate SSL CSR; reason={err.decode()}"

    # create .crt
    _, err, retcode = exec_cmd(
        f"openssl x509 -req -days 365 -in /etc/certs/{suffix}.csr "
        f"-signkey /etc/certs/{suffix}.key -out /etc/certs/{suffix}.crt"
    )
    assert retcode == 0, f"Failed to generate SSL cert; reason={err.decode()}"

    # return the paths
    return f"/etc/certs/{suffix}.crt", f"/etc/certs/{suffix}.key"


def generate_keystore(suffix, hostname, keypasswd):
    # converts key to pkcs12
    _, err, retcode = exec_cmd(
        f"openssl pkcs12 -export -inkey /etc/certs/{suffix}.key "
        f"-in /etc/certs/{suffix}.crt -out /etc/certs/{suffix}.pkcs12 "
        f"-name {hostname} -passout pass:'{keypasswd}'"
    )
    assert retcode == 0, \
        f"Failed to generate PKCS12 keystore; reason={err.decode()}"

    # imports p12 to keystore
    _, err, retcode = exec_cmd(
        f"keytool -importkeystore -srckeystore /etc/certs/{suffix}.pkcs12 "
        f"-srcstorepass {keypasswd} -srcstoretype PKCS12 "
        f"-destkeystore /etc/certs/{suffix}.jks -deststorepass {keypasswd} "
        "-deststoretype JKS -keyalg RSA -noprompt"
    )
    assert retcode == 0, \
        f"Failed to generate JKS keystore; reason={err.decode()}"
