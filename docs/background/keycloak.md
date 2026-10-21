# Keycloak

Keycloak is an open-source software product to allow single sign-on with identity and access management aimed at modern applications and services. Single sign-on (SSO) means that a user may access different applications with the same credentials.

Keycloak supports various protocols for authentication such as OpenID Connect, OAuth version 2.0 and SAML and provides features such as user management, two-factor authentication, permissions and roles management, creating token services, etc.

# Database

Keycloak has its own database where it saves data that it relies on.

Some of the data stored in its own database are:

- Users: local and imported ones
- Roles and groups: who is in which group, and which role belongs to which group.
- Sessions and tokens metadata: login sessions, refresh tokens and offline sessions
- Events and audut logs
- Signing keys

Keycloak can store passwords (hashed) for its local users, for example the admin account. For users that come from Active Directory, it only stores a copy of the user (kind of like a cache), but not their passwords. Thats why credentials of these users have to be verified by Active Directory. The local copy of the users is used e.g. for the token generation and session management.

# Realms

A realm is a separate space in Keycloak with its own users, groups, roles and clients. Users of one realm cannot log in to another. The realm `master` exists in every installation and is for the Keycloak administrators. Applications use their own realms. CloakSync reads the users of one realm (`CS_KCK_REALM`).

# Realm Import

A realm import is a JSON file that describes a realm: its settings, clients, roles, groups, and optionally users with their passwords. The file can also set IDs, for example the ID of a group.

Keycloak reads the files at startup when it runs with `--import-realm`. It imports every `*.json` file in `/opt/keycloak/data/import/`. If a realm does not exist yet, Keycloak creates it from the file. If the realm already exists, Keycloak skips it and changes nothing. So the import fills an empty Keycloak once. It does not keep Keycloak in sync with the file.

An import file can come from a running Keycloak:

- The admin console has "Partial export" in the realm settings. It exports the realm settings, clients, groups and roles, but no users, and it masks secrets.
- `kc.sh export` on the server exports a full realm, also with users.

Keycloak can import a file from an older version. It migrates the data during the import.

# Sources

<https://de.wikipedia.org/wiki/Keycloak>
<https://www.keycloak.org/>
<https://www.keycloak.org/server/importExport>
