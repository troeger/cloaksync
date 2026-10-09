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

# Sources

<https://de.wikipedia.org/wiki/Keycloak>
<https://www.keycloak.org/>
