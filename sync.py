import logging
import urllib3
import time
import os
from datetime import datetime, timezone
from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection
from kubernetes import client, config as k8s_config, dynamic
from kubernetes.client.rest import ApiException
from kubernetes.dynamic.resource import ResourceList
from dotenv import load_dotenv

from namespace_expiry import Action, Decision, ExpirySettings, NamespaceFacts, decide

# disable kubernetes requests API
urllib3.disable_warnings()

# load .env file
load_dotenv()
k8s_user_prefix = os.getenv('CS_K8S_USER_PREFIX')

# configure logging
logging.basicConfig(format="[%(levelname)s] %(asctime)s %(message)s")
level = logging.getLevelName(os.getenv('CS_LOG_LEVEL'))
logger = logging.getLogger("cloak-sync")
logger.setLevel(level)

# Connect Kubernetes
try:
    k8s_config.load_incluster_config()
except Exception:
    try:
        k8s_config.load_kube_config()
    except Exception:
        logger.error("Could not load Kubernetes configuration.")

k8s_core_api = client.CoreV1Api()
k8s_apps_api = client.AppsV1Api()
k8s_net_api = client.NetworkingV1Api()
k8s_custom_api = client.CustomObjectsApi()
k8s_dynamic_client = dynamic.DynamicClient(client.api_client.ApiClient())
policy_api = client.RbacAuthorizationV1Api()

EXPIRY_CONFIGMAP_NAME = "namespace-expiry"


def _kck_recurse_group_names_with_role(group_obj, role_name):
    names = []
    if 'realmRoles' in group_obj and role_name in group_obj['realmRoles']:
        names.append(group_obj['id'])
    for sub_group in group_obj.get('subGroups', []):
        names.extend(_kck_recurse_group_names_with_role(sub_group, role_name))  
    return names


def _kck_get_groups_with_role(keycloak_admin, role_name):
    groups = keycloak_admin.get_groups(full_hierarchy=True)
    result = []
    for group in groups:
        result.extend(_kck_recurse_group_names_with_role(group, role_name))
    return result


def kck_get_role_members(keycloak_admin, role_name):
    """
    Gets the members of a Keycloak role.
    """
    group_ids = _kck_get_groups_with_role(keycloak_admin, role_name)
    for group_id in group_ids:
        yield from kck_get_group_members(keycloak_admin, group_id)


def kck_get_group_members(keycloak_admin, group_uuid):
    """
    Gets the members of a Keycloak group recursively, including sub-group members.
    """
    group = keycloak_admin.get_group(group_uuid)
    if group['subGroupCount'] > 0:
        for subgroup in group['subGroups']:
            yield from kck_get_group_members(keycloak_admin, subgroup['id'])

    group_members = keycloak_admin.get_group_members(group_uuid, query={'briefRepresentation': 'true'})
    for member in group_members:
        yield member['username'].strip()


def k8s_get_namespaces():
    """
    Get all namespaces from Kubernetes.
    """
    ret = k8s_core_api.list_namespace(watch=False)
    all_names = [item.metadata.name for item in ret.items]
    filtered_names = [name.strip() for name in all_names if not name.startswith('kube-')]
    return filtered_names


def role_exists(role_template):
    """
    Checks if a role already exists in Kubernetes, based on
    a prepared client library data structure.
    """
    try:
        policy_api.read_namespaced_role(
            role_template.metadata.name,
            role_template.metadata.namespace
        )
    except ApiException as e:
        if e.status == 404:
            return False
        raise
    return True


def role_binding_exists(role_binding_template):
    """
    Checks if a role binding already exists in Kubernetes, based on
    a prepared client library data structure.
    """
    try:
        policy_api.read_namespaced_role_binding(
            role_binding_template.metadata.name,
            role_binding_template.metadata.namespace
        )
    except ApiException as e:
        if e.status == 404:
            return False
        raise
    return True


def ensure_owner_role_binding(namespace, user):
    """
    Ensures that the neccessary role bindings for OIDC
    access exist for the given user in the given namespace.
    """
    owner_rolename = os.getenv("CS_K8S_OWNER_ROLE_NAME")
    owner_rolebindingname = os.getenv("CS_K8S_OWNER_ROLE_BINDING_NAME")

    # create ns-specific role to enable access for user to its own namespace
    user_access_role = client.V1Role(
        metadata=client.V1ObjectMeta(
            name=owner_rolename,
            namespace=namespace
        ),
        rules=[
            client.V1PolicyRule(
                [""], resources=["*"], verbs=["*"]
            ),
            client.V1PolicyRule(
                ["extensions"], resources=["*"], verbs=["*"]
            )
        ],
    )
    if not role_exists(user_access_role):
        logger.info("  Creating namespace owner role '%s' ...", owner_rolename)
        policy_api.create_namespaced_role(namespace=namespace, body=user_access_role)
    else:
        logger.debug("  Namespace owner role '%s' already exists.", owner_rolename)

    # enable access for user to its own namespace
    user_access_role_binding = client.V1RoleBinding(
        metadata=client.V1ObjectMeta(
            name=owner_rolebindingname,
            namespace=namespace
        ),
        subjects=[
            client.RbacV1Subject(
                name=user, kind="User", api_group="rbac.authorization.k8s.io"
            )
        ],
        role_ref=client.V1RoleRef(
            api_group="rbac.authorization.k8s.io", kind="Role", name=owner_rolename
        ),
    )
    if not role_binding_exists(user_access_role_binding):
        logger.info("  Creating namespace owner role binding for '%s' ...", user)
        policy_api.create_namespaced_role_binding(namespace=namespace, body=user_access_role_binding)
    else:
        logger.debug("  Namespace owner role binding for user '%s' already exists.", user)


def ensure_additional_role_bindings(namespace, user):
    """
    Ensures that the configured additional role bindings,
    exist for the given user in the given namespace.
    """

    # Create role bindings for configured cluster roles
    clusterroles = list(os.getenv('CS_K8S_CLUSTERROLE_BINDINGS').split(','))
    logger.debug('  Checking cluster roles: %s', clusterroles)
    for role in clusterroles:
        if role != '':
            role_binding = client.V1RoleBinding(
                metadata=client.V1ObjectMeta(
                    name=role,
                    namespace=namespace
                ),
                subjects=[
                    client.RbacV1Subject(
                        name=user, kind="User", api_group="rbac.authorization.k8s.io"
                    )
                ],
                role_ref=client.V1RoleRef(
                    api_group="rbac.authorization.k8s.io", kind="ClusterRole", name=role
                ),
            )
            if not role_binding_exists(role_binding):
                logger.info("  Creating role binding for '%s' to '%s' ...", user, role)
                policy_api.create_namespaced_role_binding(namespace=namespace, body=role_binding)
            else:
                logger.debug("  Role binding for '%s' to '%s' already exists.", user, role)


def k8s_create_namespace_for_user(namespace, user):
    """
    Create a new namespace from the name of the user, and bind the user account
    of this namespace to the configured cluster roles. It also enables the access
    of the user account to the namespace itself.
    """
    # create target namespace
    namespace_obj = client.V1Namespace(
        metadata=client.V1ObjectMeta(
            name=namespace,
        ),
    )
    logger.info("  Creating namespace resource ...")
    k8s_core_api.create_namespace(namespace_obj)
    ensure_owner_role_binding(namespace, user)


def k8s_get_resources(ignored_resources=None):
    """
    Get all resource types from Kubernetes.
    """
    for api_resource in k8s_dynamic_client.resources:
        if (not isinstance(api_resource[0], ResourceList)
                and "get" in api_resource[0].verbs 
                and api_resource[0].namespaced 
                and api_resource[0].kind != "Event"):
            if api_resource[0].name not in ignored_resources:
                yield api_resource[0]


def k8s_namespace_is_empty(namespace, checked_resources):
    """
    Check if the given namespace is empty, for the given
    list of resources to be checked.
    """
    ignore_lists = {
        'ConfigMap': os.getenv('CS_K8S_PRUNING_IGNORE_CONFIGMAPS'),
        'Secret': os.getenv('CS_K8S_PRUNING_IGNORE_SECRETS'),
        'ServiceAccount': os.getenv('CS_K8S_PRUNING_IGNORE_SERVICEACCOUNTS'),
        'RoleBinding': os.getenv('CS_K8S_PRUNING_IGNORE_ROLEBINDINGS'),
    }

    for resource in checked_resources:
        resource_instance = resource.get(namespace=namespace)
        items = resource_instance.items
        for item in items:
            resource_type = item.kind
            resource_name = item.metadata.name
            item_ignored = False
            for k, v in ignore_lists.items():
                if resource_type == k:
                    for ignore_entry in v.split(','):
                        if resource_name.startswith(ignore_entry):
                            # resource is in ignore list for empty namespace check
                            logger.debug("  Ignoring %s:%s", resource_type, resource_name)
                            item_ignored = True
                            break
            if not item_ignored:
                logger.debug("  Found %s: %s", item.kind, item.metadata.name)
                return False
    return True


def expiry_load_settings() -> ExpirySettings:
    """
    Loads the namespace expiry settings from the environment.
    """
    reminder_days = os.getenv('CS_EXPIRY_REMINDER_DAYS').split(',')
    return ExpirySettings(
        extension_days=int(os.getenv('CS_EXPIRY_EXTENSION_DAYS')),
        suspension_days=int(os.getenv('CS_EXPIRY_SUSPENSION_DAYS')),
        reminder_days=tuple(int(days) for days in reminder_days if days.strip()),
    )


def k8s_get_namespace_creation_times() -> dict[str, datetime]:
    """
    Gets the creation time of every namespace, by namespace name.
    """
    ret = k8s_core_api.list_namespace(watch=False)
    return {item.metadata.name: item.metadata.creation_timestamp for item in ret.items}


def kck_user_has_email(keycloak_admin: KeycloakAdmin, username: str) -> bool:
    """
    Checks if the Keycloak user has an email address.
    """
    users = keycloak_admin.get_users(query={'username': username, 'exact': True, 'max': 1})
    return bool(users and users[0].get('email'))


def ensure_expiry_configmap(namespace: str) -> None:
    """
    Ensures that the namespace has the ConfigMap that users label to extend it.
    """
    try:
        k8s_core_api.read_namespaced_config_map(EXPIRY_CONFIGMAP_NAME, namespace)
        logger.debug("  Expiry: ConfigMap '%s' already exists.", EXPIRY_CONFIGMAP_NAME)
    except ApiException as e:
        if e.status != 404:
            raise
        logger.info("  Expiry: would create ConfigMap '%s' (not implemented).", EXPIRY_CONFIGMAP_NAME)


def run_expiry_action(namespace: str, decision: Decision) -> None:
    """
    Carries out the expiry decision for a namespace.
    """
    match decision.action:
        case Action.NONE:
            logger.debug("  Expiry: nothing to do.")
        case Action.SEND_REMINDER:
            if decision.moves_deadline:
                logger.info("  Expiry: would move the deadline to %s, the reminder is late (not implemented).",
                            decision.deadline.date())
            logger.info("  Expiry: would send the %u-day reminder to '%s' (not implemented).",
                        decision.reminder_days, namespace)
        case Action.SUSPEND:
            logger.info("  Expiry: would suspend the namespace (not implemented).")
        case Action.RESTORE:
            logger.info("  Expiry: would restore the namespace (not implemented).")
        case Action.DELETE:
            logger.info("  Expiry: would delete the namespace (not implemented).")
        case Action.ADMIN_REVIEW:
            logger.info("  Expiry: would report the namespace for admin review: %s (not implemented).", decision.reason)


def check_namespace_expiry(namespace: str, created_at: datetime, has_owner: bool,
                           keycloak_admin: KeycloakAdmin, settings: ExpirySettings, now: datetime) -> None:
    """
    Decides what namespace expiry does for the given namespace, and does it.
    """
    ensure_expiry_configmap(namespace)
    # The namespace name is the Keycloak username of its owner.
    email_known = has_owner and kck_user_has_email(keycloak_admin, namespace)
    # There is no stored state yet: nobody has extended, no reminder went out
    # and no deadline was moved.
    facts = NamespaceFacts(
        name=namespace,
        created_at=created_at,
        last_extension_at=None,
        last_reminder_at=None,
        moved_deadline=None,
        owner_email_known=email_known,
        suspended=False,
    )
    decision = decide(facts, settings, now)
    logger.info("  Expiry: deadline %s, status %s.", decision.deadline.date(), decision.status.value)
    run_expiry_action(namespace, decision)

###


while True:
    # Connect Keycloak
    logger.info("Connecting to Keycloak ...")
    keycloak_connection = KeycloakOpenIDConnection(server_url=os.getenv('CS_KCK_SERVER'),
                                                   realm_name=os.getenv('CS_KCK_REALM'),
                                                   user_realm_name=os.getenv('CS_KCK_REALM'),
                                                   client_id=os.getenv('CS_KCK_CLIENT_ID'),
                                                   client_secret_key=os.getenv('CS_KCK_CLIENT_SECRET'),
                                                   verify=True)
    keycloak_adm = KeycloakAdmin(connection=keycloak_connection)

    # Fetch Kubernetes users from Keycloak
    logger.info("Fetching users from Keycloak ...")
    kck_users = list(kck_get_group_members(keycloak_adm, os.getenv('CS_KCK_GROUP_UUID')))
    logger.debug("Keycloak group users: %s", list(kck_users))
    kck_role_users = list(kck_get_role_members(keycloak_adm, os.getenv('CS_KCK_ROLE_NAME')))
    logger.debug("Keycloak role users: %s", list(kck_role_users))
    kck_users.extend(x for x in kck_role_users if x not in kck_users)
    logger.debug("Keycloak users being relevant: %s", list(kck_users))

    # Fetch Kubernetes namespaces
    logger.info("Fetching namespaces from Kubernetes ...")
    k8s_namespaces = k8s_get_namespaces()

    # Compute the effective set of namespaces, based on restrictions
    k8s_ns_ignore = os.getenv('CS_K8S_IGNORE_NAMESPACES', default='default,cert-manager,ingress-nginx').split(',')
    k8s_effective_ns = [ns for ns in k8s_namespaces if ns not in k8s_ns_ignore]
    logger.debug("Effective Kubernetes namespaces: %s", k8s_effective_ns)

    # Compute diff, based on the full view of existing namespaces
    missing_in_k8s = [item for item in kck_users if item not in k8s_namespaces]
    logger.debug("Missing in Kubernetes: %s", missing_in_k8s)
    missing_ns_in_kck = [item for item in k8s_namespaces if item not in kck_users]
    logger.debug("Missing in Keycloak: %s", missing_ns_in_kck)

    # Create missing Kubernetes namespaces for Keycloak users
    if len(missing_in_k8s) == 0:
        logger.info("All Keycloak users have corresponding namespaces.")
    else:
        for kck_user in missing_in_k8s:
            logger.info("Keycloak user '%s' has no namespace, creating it.", kck_user)
            k8s_create_namespace_for_user(kck_user, k8s_user_prefix + kck_user)

    # Determine Kubernetes resource types to be considered
    resources = list(k8s_get_resources(os.getenv('CS_K8S_PRUNING_IGNORE_RESOURCES').split(',')))

    # Go through the list of namespaces that we should have a look upon
    logger.info("Checking namespaces for validity.")
    pruning_check = os.getenv('CS_K8S_PRUNING_CHECK').lower() in ("yes", "true", "t", "1")
    pruning_delete = os.getenv('CS_K8S_PRUNING_DELETE').lower() in ("yes", "true", "t", "1")
    expiry_check = os.getenv('CS_EXPIRY_CHECK').lower() in ("yes", "true", "t", "1")
    if expiry_check:
        try:
            expiry_settings = expiry_load_settings()
            namespace_creation_times = k8s_get_namespace_creation_times()
            now = datetime.now(timezone.utc)
        except Exception:
            # A failing expiry setup must not stop the sync of the namespaces.
            logger.exception("Expiry: setup failed, skipping the expiry check in this run.")
            expiry_check = False
    for ns in k8s_effective_ns:
        logger.debug("Checking namespace '%s' ...", ns)
        if ns in missing_ns_in_kck:
            logger.info("Namespace '%s' has no corresponding Keycloak user.", ns)
            if pruning_check:
                # Prune empty Kubernetes namespaces that do not have a matching Keycloak user
                if k8s_namespace_is_empty(ns, resources):
                    logger.info("  Namespace is empty.")
                    if pruning_delete:
                        logger.info("  Would delete the empty namespace (not implemented).")
                    else:
                        logger.info("  Deletion of empty namespaces is disabled, not touching it.")
                else:
                    logger.info("  Namespace has resources and is not empty.")
        else:
            logger.info("Namespace '%s' has a corresponding Keycloak user, checking for validity ...", ns)
            ensure_owner_role_binding(ns, k8s_user_prefix + ns)
            ensure_additional_role_bindings(ns, k8s_user_prefix + ns)

        if expiry_check and ns in namespace_creation_times:
            try:
                check_namespace_expiry(ns, namespace_creation_times[ns], ns not in missing_ns_in_kck,
                                       keycloak_adm, expiry_settings, now)
            except Exception:
                # A failing expiry check must not stop the sync of the other namespaces.
                logger.exception("  Expiry: check failed for namespace '%s'.", ns)

    # Sleep until next run
    sleep_time = int(os.getenv('CS_KCK_POLL_INTERVAL'))
    logger.debug("Waiting %u seconds for next check.", sleep_time)
    time.sleep(sleep_time)
