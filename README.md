# CloakSync

CloakSync is a docker-based daemon that synchronizes your Keycloak
user database with your OIDC-enabled Kubernetes cluster. You want to 
use this deaemon if:

  - You have Keycloak and Kubernetes in place.
  - Your Keycloak installation is handling the user authentication.
  - Your Kubernetes API server uses this Keycloak installation for authentication (see XXX for details).
  - Keycloak users are organized in groups. 
  - Every Keycloak user that is part of a defined group should have Kubernetes cluster access, with her own private namespace.

CloakSync can be used as light-weight alternative for Rancher and other full-fledged
solutions for OIDC-enabled user management.

## Installation

CloakSync is expected to be deployed on the target Kubernetes cluster. The folder `deployment` contains all necccessary information.

## CloakSync Configuration

CloakSync is configured through environment variables. Please set them accordingly when deployment the Docker image to your Kubernetes cluster, f.e. with a ConfigMap.

| Environment variable  | Description | Example | mandatory? |
|CS_LOG_LEVEL | Log level (DEBUG, INFO, WARN, ERROR, CRITICAL) | DEBUG | yes |
|CS_KCK_SERVER  | Root URL of your Keycloak server |  https://auth.example.com | yes |
|CS_KCK_REALM | Name of your Keycloak realm, f.e. | cluster | yes |
|CS_KCK_CLIENT_ID | Client ID configured in Keycloak for the Kubernetes API server | k8s | yes |
|CS_KCK_CLIENT_SECRET | Client Secret configured in Keycloak for the Kubernetes API server | abc123 | yes |
|CS_KCK_GROUP_UUID  | UUID of the Keycloak user group allowing Kubernetes access. The UUID can be obtained from the Keycloak URL of the group details.  | 123hvd65 ] yes |
|CS_K8S_CLUSTERROLE_BINDINGS  | Comma-separated list of ClusterRole names that should be enabled for Kubernetes users | no |
|CS_K8S_USER_PREFIX | Prefix for user names in Kubernetes. Must match to the Kubernetes API server configuration | keycloak: | no |
|CS_K8S_OWNER_ROLE_NAME | Name of the role generated for personal namespace access | namespace-owner | yes |
|CS_K8S_OWNER_ROLE_BINDING_NAME | Name of the role generated for personal namespace access | namespace-owner | yes |
|CS_K8S_IGNORE_NAMESPACES | Comma-separated list of Kubernetes namespaces to be ignored | default,ingress-nginx,rook-ceph | no |
|CS_K8S_PRUNING_CHECK | Should existing Kubernetes namespaces being checked for correct configuration? | yes | yes |
|CS_K8S_PRUNING_DELETE  | Should Kubernetes namespaces with no resources be deleted? | no | yes |
|CS_K8S_PRUNING_IGNORE_CONFIGMAPS | Comma-separated list of ConfigMap resources to be ignored when CS_K8S_PRUNING_DELETE=true |  | no |
|CS_K8S_PRUNING_IGNORE_SECRETS  | Comma-separated list of Secret resources to be ignored when CS_K8S_PRUNING_DELETE=true |  | no |
|CS_K8S_PRUNING_IGNORE_SERVICEACCOUNTS  |  Comma-separated list of ServiceAccount resources to be ignored when CS_K8S_PRUNING_DELETE=true |  | no |
|CS_K8S_PRUNING_IGNORE_ROLEBINDINGS | Comma-separated list of RoleBinding resources to be ignored when CS_K8S_PRUNING_DELETE=true |  | no |
|CS_K8S_PRUNING_IGNORE_RESOURCES  | Comma-separated list of Resource resources to be ignored when CS_K8S_PRUNING_DELETE=true |  | no |

## Keycloak configuration

- Change the existing "admin-cli" client in the realm
- Switch to "Service account roles" in the authentication flow settings
- In the "service account roles" tab, add the "realm-admin" role

## Kubernetes API Server configuration

TBD

