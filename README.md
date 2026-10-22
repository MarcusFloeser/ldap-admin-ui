<img width="500" alt="image" src="https://github.com/user-attachments/assets/a3633a78-fc3b-4a89-b4aa-b00c9cb66ba5" />
<img width="500" alt="image" src="https://github.com/user-attachments/assets/04cae86b-97ba-47a0-a325-0e7fd2de61cb" />


# ldap-admin-ui
A simple Admin UI for administering openldap server content

Prerequisite:
- docker compose
- a running openldap server

It is strongly recommended to run the ui behind a reverse proxy (traefik, nginx ..)

## Create .env file with following entries:
```
# URL for your LDAP server
LDAP_URI=ldap://openldap:389
# LDAP base
LDAP_BASE=dc=example,dc=org
# OU for users for login (needed if login should be possible with short name instead of DN)
LDAP_USERS=ou=admins,ou=users
# random key, create it with:  openssl rand -hex 32
SECRET_KEY=
# on which ip should it listen? 0.0.0.0 for all
LISTEN=127.0.0.1
# which port should be exposed?
PORT=8080
# which account can write to cn=config (for access right changes) ?
LDAP_CONFIG_DN=cn=admin,cn=config
# Title for the application
APP_TITLE=Example Org's ldap tree
```
## docker-compose.yml:
```
services:
  ldap-admin:
    image: ghcr.io/marcusfloeser/ldap-admin-ui:latest
    container_name: ldap-admin
    restart: unless-stopped
    ports:
      - "${LISTEN:-127.0.0.1}:${PORT:-8080}:8080"
    environment:
      LDAP_URI: ${LDAP_URI:?Please set LDAP_URI in .env }
      LDAP_BASE: ${LDAP_BASE:?Please set LDAP_BASE in .env }
      LDAP_USERS: ${LDAP_USERS:-ou=people}
      SECRET_KEY: ${SECRET_KEY:?Please set SECRET_KEY in .env}
      LDAP_CONFIG_DN: ${LDAP_CONFIG_DN:-cn=admin,cn=config}
      APP_TITLE: ${APP_TITLE:-directory}
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
