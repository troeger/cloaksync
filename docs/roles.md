# Roles and Permissions

Kubernetes and Keycloak both define their own role system. Namely:

- From Keycloak: Groups and Roles
- From K8s: Roles, RoleBindings, ClusterRoles, ClusterRoleBindings

The two sides do different jobs. Keycloak groups and roles decide who is a cluster user. K8s roles and bindings decide what a user may do in the cluster. CloakSync connects the two: it reads the Keycloak side and writes the K8s side.

## Kubernetes Permissions for Users

For each user in Keycloak a K8s namespace should be created (if there doesn't exist one yet). The namespace has the same name as the Keycloak username. Then, a Role is created in that namespace. This Role has rules that allow all verbs on all resources of the core API group (Pods, Services, PVC, etc.), but only inside that namespace. The role is called the owner role because its supposed to make the user the owner of their namespace. A RoleBinding that binds the owner role to the user is also created. From that point onward, the user can control the basic K8s functionality in their own namespace. This is all done via the Kubernetes Python library in [sync.py](../sync.py).

The owner Role does not cover other API groups, for example Deployments (`apps`), Ingresses (`networking.k8s.io`) or custom resources. For this, CloakSync can create extra RoleBindings. `CS_K8S_CLUSTERROLE_BINDINGS` holds a comma-separated list of ClusterRole names. For each name, CloakSync creates a RoleBinding in the user's namespace that points at that ClusterRole. Using ClusterRoles as a template for Roles is the intended way to use role templates in K8s. Because it is a RoleBinding, the extra rights apply only in the user's own namespace. CloakSync does not create these ClusterRoles. They must already exist in the cluster, either built-in or created by an admin.

## Kubernetes Permissions for CloakSync

CloakSync itself needs to be able to create namespaces, and hand out Roles and RoleBindings for them. Since this must work across the whole cluster, a ClusterRole is needed for it. [rbac.yml](../deployment/k8s/base/rbac.yml) holds the ClusterRole and the ClusterRoleBinding for cloaksync. CloakSync runs as the `default` ServiceAccount of the `cloaksync` namespace, which is the subject of the ClusterRoleBinding.

## Service Accounts of CloakSync

Keycloak and Kubernetes each have their own concept of a service account. CloakSync uses one in each system:

1. The Keycloak service account lets CloakSync read users and groups from Keycloak. Strictly, what is registered in Keycloak is a client (`admin-cli`), not an account. When "service accounts" are enabled on that client, Keycloak creates a hidden user for it. CloakSync logs in with the client ID and secret (`CS_KCK_CLIENT_ID` and `CS_KCK_CLIENT_SECRET`) and acts as that user.
2. The Kubernetes ServiceAccount lets CloakSync change the cluster. CloakSync runs as the `default` ServiceAccount of the `cloaksync` namespace. The ClusterRoleBinding gives it the ClusterRole from the section above. With it, CloakSync can create cluster-wide resources such as namespaces, among other things.

## Selecting Users in Keycloak

A Keycloak group is a named set of users. Groups can be nested. A group can have subgroups, which have their own members. A Keycloak role is a named label for a permission, for example `k8s-user`. A role can be given to a user directly, or to a group, and then every member of the group has it. Within Keycloak, these roles do not control anything here. CloakSync only reads them.

CloakSync needs to know which users it should do its job for. It finds the relevant users in two ways and joins the two lists:

1. All members of the Keycloak group with the UUID `CS_KCK_GROUP_UUID`, including the members of all its subgroups.
2. All members of each Keycloak group that has the realm role `CS_KCK_ROLE_NAME` assigned directly, again including subgroup members.

So a user gets access by being put into one of these groups. In our setup, selected individuals do this through a UI.
