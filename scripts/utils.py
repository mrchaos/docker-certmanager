from pygluu.containerlib.utils import exec_cmd


def generate_ssl_certkey(suffix, passwd, email, hostname, org_name,
                         country_code, state, city):
    # create key with password
    _, err, retcode = exec_cmd(" ".join([
        "openssl",
        "genrsa -des3",
        "-out /etc/certs/{}.key.orig".format(suffix),
        "-passout pass:'{}' 2048".format(passwd),
    ]))
    assert retcode == 0, "Failed to generate SSL key with password; reason={}".format(err)

    # create .key
    _, err, retcode = exec_cmd(" ".join([
        "openssl",
        "rsa",
        "-in /etc/certs/{}.key.orig".format(suffix),
        "-passin pass:'{}'".format(passwd),
        "-out /etc/certs/{}.key".format(suffix),
    ]))
    assert retcode == 0, "Failed to generate SSL key; reason={}".format(err)

    # create .csr
    _, err, retcode = exec_cmd(" ".join([
        "openssl",
        "req",
        "-new",
        "-key /etc/certs/{}.key".format(suffix),
        "-out /etc/certs/{}.csr".format(suffix),
        """-subj /C="{}"/ST="{}"/L="{}"/O="{}"/CN="{}"/emailAddress='{}'""".format(country_code, state, city, org_name, hostname, email),

    ]))
    assert retcode == 0, "Failed to generate SSL CSR; reason={}".format(err)

    # create .crt
    _, err, retcode = exec_cmd(" ".join([
        "openssl",
        "x509",
        "-req",
        "-days 365",
        "-in /etc/certs/{}.csr".format(suffix),
        "-signkey /etc/certs/{}.key".format(suffix),
        "-out /etc/certs/{}.crt".format(suffix),
    ]))
    assert retcode == 0, "Failed to generate SSL cert; reason={}".format(err)

    # return the paths
    return "/etc/certs/{}.crt".format(suffix), \
           "/etc/certs/{}.key".format(suffix)


def generate_keystore(suffix, hostname, keypasswd):
    # converts key to pkcs12
    cmd = " ".join([
        "openssl",
        "pkcs12",
        "-export",
        "-inkey /etc/certs/{}.key".format(suffix),
        "-in /etc/certs/{}.crt".format(suffix),
        "-out /etc/certs/{}.pkcs12".format(suffix),
        "-name {}".format(hostname),
        "-passout pass:'{}'".format(keypasswd),
    ])
    _, err, retcode = exec_cmd(cmd)
    assert retcode == 0, "Failed to generate PKCS12 keystore; reason={}".format(err)

    # imports p12 to keystore
    cmd = " ".join([
        "keytool",
        "-importkeystore",
        "-srckeystore /etc/certs/{}.pkcs12".format(suffix),
        "-srcstorepass {}".format(keypasswd),
        "-srcstoretype PKCS12",
        "-destkeystore /etc/certs/{}.jks".format(suffix),
        "-deststorepass {}".format(keypasswd),
        "-deststoretype JKS",
        "-keyalg RSA",
        "-noprompt",
    ])
    _, err, retcode = exec_cmd(cmd)
    assert retcode == 0, "Failed to generate JKS keystore; reason={}".format(err)
