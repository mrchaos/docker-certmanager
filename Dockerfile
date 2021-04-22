FROM alpine:3.13

# ===============
# Alpine packages
# ===============

RUN apk update \
    && apk add --no-cache openssl py3-pip curl tini openjdk11-jre-headless py3-cryptography \
    && apk add --no-cache --virtual build-deps wget git \
    && mkdir -p /usr/java/latest \
    && ln -sf /usr/lib/jvm/default-jvm/jre /usr/java/latest/jre

# =============
# oxAuth client
# =============

# JAR files required to generate OpenID Connect keys
ENV GLUU_VERSION=4.2.3.Final
ENV GLUU_BUILD_DATE="2021-03-10 10:37"

RUN mkdir -p /app/javalibs \
    && wget -q https://ox.gluu.org/maven/org/gluu/oxauth-client/${GLUU_VERSION}/oxauth-client-${GLUU_VERSION}-jar-with-dependencies.jar -O /app/javalibs/oxauth-client.jar

# =================
# Shibboleth sealer
# =================

RUN mkdir -p /app/javalibs \
    && wget -q https://build.shibboleth.net/nexus/content/repositories/releases/net/shibboleth/utilities/java-support/7.5.1/java-support-7.5.1.jar -O /app/javalibs/java-support.jar \
    && wget -q https://repo1.maven.org/maven2/com/beust/jcommander/1.48/jcommander-1.48.jar -O /app/javalibs/jcommander.jar \
    && wget -q https://repo1.maven.org/maven2/org/slf4j/slf4j-api/1.7.26/slf4j-api-1.7.26.jar -O /app/javalibs/slf4j-api.jar \
    && wget -q https://repo1.maven.org/maven2/org/slf4j/slf4j-simple/1.7.26/slf4j-simple-1.7.26.jar -O /app/javalibs/slf4j-simple.jar

# ======
# Python
# ======

COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -U pip \
    && pip3 install --no-cache-dir -r /app/requirements.txt \
    && rm -rf /src/pygluu-containerlib/.git

# =======
# Cleanup
# =======

RUN apk del build-deps \
    && rm -rf /var/cache/apk/*

# =======
# License
# =======

RUN mkdir -p /licenses
COPY LICENSE /licenses/

# ==========
# Config ENV
# ==========

ENV GLUU_CONFIG_ADAPTER=consul \
    GLUU_CONFIG_CONSUL_HOST=localhost \
    GLUU_CONFIG_CONSUL_PORT=8500 \
    GLUU_CONFIG_CONSUL_CONSISTENCY=default \
    GLUU_CONFIG_CONSUL_SCHEME=http \
    GLUU_CONFIG_CONSUL_VERIFY=false \
    GLUU_CONFIG_CONSUL_CACERT_FILE=/etc/certs/consul_ca.crt \
    GLUU_CONFIG_CONSUL_CERT_FILE=/etc/certs/consul_client.crt \
    GLUU_CONFIG_CONSUL_KEY_FILE=/etc/certs/consul_client.key \
    GLUU_CONFIG_CONSUL_TOKEN_FILE=/etc/certs/consul_token \
    GLUU_CONFIG_KUBERNETES_NAMESPACE=default \
    GLUU_CONFIG_KUBERNETES_CONFIGMAP=gluu \
    GLUU_CONFIG_KUBERNETES_USE_KUBE_CONFIG=false

# ==========
# Secret ENV
# ==========

ENV GLUU_SECRET_ADAPTER=vault \
    GLUU_SECRET_VAULT_SCHEME=http \
    GLUU_SECRET_VAULT_HOST=localhost \
    GLUU_SECRET_VAULT_PORT=8200 \
    GLUU_SECRET_VAULT_VERIFY=false \
    GLUU_SECRET_VAULT_ROLE_ID_FILE=/etc/certs/vault_role_id \
    GLUU_SECRET_VAULT_SECRET_ID_FILE=/etc/certs/vault_secret_id \
    GLUU_SECRET_VAULT_CERT_FILE=/etc/certs/vault_client.crt \
    GLUU_SECRET_VAULT_KEY_FILE=/etc/certs/vault_client.key \
    GLUU_SECRET_VAULT_CACERT_FILE=/etc/certs/vault_ca.crt \
    GLUU_SECRET_KUBERNETES_NAMESPACE=default \
    GLUU_SECRET_KUBERNETES_SECRET=gluu \
    GLUU_SECRET_KUBERNETES_USE_KUBE_CONFIG=false

# ===============
# Persistence ENV
# ===============

ENV GLUU_PERSISTENCE_TYPE=couchbase \
    GLUU_PERSISTENCE_LDAP_MAPPING=default \
    GLUU_COUCHBASE_URL=localhost \
    GLUU_COUCHBASE_USER=admin \
    GLUU_COUCHBASE_CERT_FILE=/etc/certs/couchbase.crt \
    GLUU_COUCHBASE_PASSWORD_FILE=/etc/gluu/conf/couchbase_password \
    GLUU_COUCHBASE_SUPERUSER="" \
    GLUU_COUCHBASE_SUPERUSER_PASSWORD_FILE=/etc/gluu/conf/couchbase_superuser_password \
    GLUU_COUCHBASE_BUCKET_PREFIX=gluu \
    GLUU_LDAP_URL=localhost:1636

# ===========
# Generic ENV
# ===========

ENV GLUU_WAIT_MAX_TIME=300 \
    GLUU_WAIT_SLEEP_DURATION=10 \
    GLUU_CONTAINER_METADATA=docker

# ====
# misc
# ====

LABEL name="Certmanager" \
    maintainer="Gluu Inc. <support@gluu.org>" \
    vendor="Gluu Federation" \
    version="4.2.3" \
    release="06" \
    summary="Gluu Certmanager" \
    description="Manage certs and crypto keys for Gluu Server"

COPY scripts /app/scripts

RUN mkdir -p /etc/certs \
    && chmod +x /app/scripts/entrypoint.sh

ENTRYPOINT ["tini", "-g", "--", "sh", "/app/scripts/entrypoint.sh"]
CMD ["--help"]
