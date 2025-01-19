# CloakSync

CloakSync is a docker-based daemon that makes sure that your Keycloak
users have access to your OIDC-enabled Kubernetes cluster. It generates 
a private namespace for each Keycloak user, and makes sure that all
neccessary role bindings for access are set. Kubernetes users are identified 
in Keycloak by membership in a Keycloak user group.

You want to use this deaemon if:

  - You have Keycloak and Kubernetes in place.
  - Your Keycloak installation is handling the authentication of your users.
  - Your Kubernetes API server uses this Keycloak installation for authentication (see this [Medium article](https://medium.com/elmo-software/kubernetes-authenticating-to-your-cluster-using-keycloak-eba81710f49b) for details).
  - Keycloak users are organized in groups. 
  - Every Keycloak user that is part of a defined group should have Kubernetes cluster access, with her own private namespace.

CloakSync can be used as light-weight alternative for Rancher and other full-fledged
solutions with identity provider support. 

## Installation

CloakSync is expected to be deployed on the target Kubernetes cluster. The folder `deployment` contains all necccessary information.

## Configuration

CloakSync is configured through environment variables. Please set them accordingly when deploying the Docker image to your Kubernetes cluster, as described below. 

| Environment variable | Description | Example | mandatory? |
| -------------------- | ----------- | ------- | ---------- |
| CS_LOG_LEVEL | Log level (DEBUG, INFO, WARN, ERROR, CRITICAL) | DEBUG | no |
| CS_KCK_POLL_INTERVAL | Polling interval in Keycloak, in seconds | 60 | no |
| CS_KCK_SERVER  | Root URL of your Keycloak server |  https://auth.example.com | yes |
| CS_KCK_REALM | Name of your Keycloak realm, f.e. | cluster | yes |
| CS_KCK_CLIENT_ID | Client ID configured in Keycloak for the Kubernetes API server | admin-cli | yes |
| CS_KCK_CLIENT_SECRET | Client Secret configured in Keycloak for the Kubernetes API server | abc123 | yes |
| CS_KCK_GROUP_UUID  | UUID of the Keycloak user group allowing Kubernetes access. The UUID can be obtained from the Keycloak URL of the group details. The group can be a parent group for other groups, users are collected recursively. | 123hvd65 | yes |
| CS_KCK_ROLE_NAME | The name of a role allowing Kubernetes access. The resulting user accounts from this setting and CS_KCK_GROUP_UUID are combined. The role must be directly assigned to the group, and not only being inherited from a parent group. | k8s-user | yes |
| CS_K8S_CLUSTERROLE_BINDINGS  | Comma-separated list of ClusterRole names that should be enabled for Kubernetes users | no | no |
| CS_K8S_USER_PREFIX | Prefix for user names in Kubernetes. Must match to the Kubernetes API server configuration | keycloak: | no |
| CS_K8S_OWNER_ROLE_NAME | Name of the role generated for personal namespace access | namespace-owner | no |
| CS_K8S_OWNER_ROLE_BINDING_NAME | Name of the role generated for personal namespace access | namespace-owner | no |
| CS_K8S_IGNORE_NAMESPACES | Comma-separated list of Kubernetes namespaces to be ignored | default,ingress-nginx,rook-ceph | no |
| CS_K8S_PRUNING_CHECK | Should existing Kubernetes namespaces being checked for correct configuration? | yes | no |
| CS_K8S_PRUNING_DELETE  | Should Kubernetes namespaces with no resources be deleted? | no | no |
| CS_K8S_PRUNING_IGNORE_CONFIGMAPS | Comma-separated list of ConfigMap resources to be ignored when CS_K8S_PRUNING_DELETE=true |  | no |
| CS_K8S_PRUNING_IGNORE_SECRETS  | Comma-separated list of Secret resources to be ignored when CS_K8S_PRUNING_DELETE=true |  | no |
| CS_K8S_PRUNING_IGNORE_SERVICEACCOUNTS  |  Comma-separated list of ServiceAccount resources to be ignored when CS_K8S_PRUNING_DELETE=true |  | no |
| CS_K8S_PRUNING_IGNORE_ROLEBINDINGS | Comma-separated list of RoleBinding resources to be ignored when CS_K8S_PRUNING_DELETE=true |  | no |
| CS_K8S_PRUNING_IGNORE_RESOURCES  | Comma-separated list of Resource resources to be ignored when CS_K8S_PRUNING_DELETE=true |  | no |

## Keycloak configuration

Given the fact that CloaksSync needs to read the user database of your realm, it is the easiest way to modify the existing "admin-cli" client in your Keycloak realm for remote usage by CloakSync. You need to make the following adjustments:

- Go to the configuration page for the existing "admin-cli" client in the realm
- Got to "Service account roles" in the authentication flow settings
- In the "service account roles" tab, add the "realm-admin" role

This change allows you to fetch the value for CS_KCK_CLIENT_SECRET from the Credentials tab. The value for CS_KCK_CLIENT_ID is "admin-cli" in this case.

## Kubernetes API Server configuration

Follow the details in this [Medium article](https://medium.com/elmo-software/kubernetes-authenticating-to-your-cluster-using-keycloak-eba81710f49b) for configuration the basic integration between Keycloak and the Kubernetes API server. 

## Kubernetes deployment of CloakSync

Make a checkout of this Git repository. Create an `.env` file in `deployment/k8s/production/`, and add your tailored environment variables.
You can use the file `.env-default` in the project root as example.

When the file exists, call `kubectl apply -k deployment/k8s/production` to deploy the application with your configuration.


