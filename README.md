# ldap-admin-ui
A simple Admin UI for administering openldap server content

Prerequisite:
- docker compose
- a running openldap server

## Create .env file with following entries:
```
# URL for your LDAP server
LDAP_URI=ldap://openldap:389
LDAP_BASE=dc=example,dc=org
# OU der Benutzer, nur nötig für den Login mit einfachem Benutzernamen (statt vollem DN)
LDAP_USERS=ou=users
# Zufälliger Schlüssel:  openssl rand -hex 32
SECRET_KEY=
LISTEN=127.0.0.1
PORT=8080
# Vorbelegung für das Konto, das in cn=config schreiben darf (Zugriffsrechte)
#LDAP_CONFIG_DN=cn=admin,cn=config
```
## docker-compose.yml:
```
services:
  ldap-admin:
    image: ghcr.io/marcusfloeser/ldap-admin-ui:latest
    container_name: ldap-admin
    restart: unless-stopped
    ports:
      # Standard: nur lokal erreichbar. Für Zugriff aus dem Netz LISTEN=0.0.0.0 in .env setzen
      # (besser: hinter einen HTTPS-Reverse-Proxy stellen).
      - "${LISTEN:-127.0.0.1}:${PORT:-8080}:8080"
    environment:
      LDAP_URI: ${LDAP_URI:?Bitte LDAP_URI in .env setzen}
      LDAP_BASE: ${LDAP_BASE:?Bitte LDAP_BASE in .env setzen}
      LDAP_USERS: ${LDAP_USERS:-ou=people}
      SECRET_KEY: ${SECRET_KEY:?Bitte SECRET_KEY in .env setzen}
      LDAP_CONFIG_DN: ${LDAP_CONFIG_DN:-cn=admin,cn=config}
    # Erreichbarkeit eines LDAP-Servers auf dem Docker-Host: LDAP_URI=ldap://host.docker.internal:389
    extra_hosts:
      - "host.docker.internal:host-gateway"
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/', timeout=3)"]
      interval: 30s
      timeout: 5s
      retries: 3

```
