# OIDC

OpenID Connect (OIDC) is an authentication protocol. It is an identity layer on top of the OAuth 2.0 framework. It reuses the token flow that OAuth is built upon, and adds an ID Token to it.

# Relation to OAuth

OAuth 2.0 handles authorization: it grants a client an Access Token to access resources. OIDC adds authentication on top: it tells the client who the user is. It uses the same flow as OAuth, and the OP returns an ID Token in addition to the Access Token. The ID Token is a signed JWT with claims about the user.

# Key Components

- Relying Party (RP): An application or website that outsources its user authentication function to an IDP.
- OpenID Provider (OP): an entity that has implemented the OpenID Connect and OAuth 2.0 protocols, OP’s can sometimes be referred to by the role it plays, such as: a security token service, an identity provider (IDP), or an authorization server.

# Workflow

- End user navigates to a website or web application via a browser.
- End user clicks sign-in. The RP (Client) redirects the browser to the OpenID Provider (OP).
- The OP shows its login page. The user types their username and password there, so the RP never sees the password.
- The OP authenticates the user and obtains authorization.
- The OP responds with an ID Token and usually an Access Token.
- The RP can send a request with the Access Token to the UserInfo Endpoint of the OP.
- The UserInfo Endpoint returns Claims about the End-User.

# Sources

<https://openid.net/developers/how-connect-works/>
<https://openid.net/specs/openid-connect-core-1_0.html>
<https://www.keycloak.org/securing-apps/oidc-layers>
