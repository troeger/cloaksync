# Test Environment

The test environment is a local Kubernetes cluster in minikube. It tries to match our production cluster so that it (hopefully) behaves similarly. In that way, we can use it to test changes before running them on the real cluster.

## Setup

### Prerequisites

Docker and minikube. Each minikube release supports a range of Kubernetes versions, and the start command below selects one, so the locally installed minikube version does not have to match the cluster exactly.

### Start the Cluster

```bash
minikube start -p cloaksync-test --keep-context --driver=docker --kubernetes-version=v1.35.7
```

- `-p cloaksync-test` names the minikube profile. The profile name is also the name of the kube context that the commands below use. [Minikube](background/minikube.md) explains profiles and contexts.
- `--keep-context` stops minikube from changing your current kube context.
- `--driver=docker` runs the cluster in a Docker container. See [Minikube Runs with the Docker Driver](#minikube-runs-with-the-docker-driver).
- `--kubernetes-version` should be the production Kubernetes version. See [Versions Match Production](#versions-match-production).

### Deploy Keycloak

```bash
kubectl --context cloaksync-test apply -k deployment/k8s/test/keycloak
kubectl --context cloaksync-test -n keycloak-test rollout status deploy/keycloak
```

If the rollout status does not finish, Keycloak did not start. Its log shows why, for example a realm import that failed:

```bash
kubectl --context cloaksync-test -n keycloak-test logs deploy/keycloak
```

At startup, Keycloak imports the realm `cluster` from [realm-cluster.json](../deployment/k8s/test/keycloak/realm-cluster.json). Its web consoles are available through a port-forward:

```bash
kubectl --context cloaksync-test -n keycloak-test port-forward svc/keycloak 8080:8080
```

- The admin console is at <http://localhost:8080/admin>. The user and the password are both `admin`. Here you see and change the users, groups and roles of the realm.
- The account console is at <http://localhost:8080/realms/cluster/account>. Here a test user logs in with the password from the realm import.

### Deploy CloakSync

```bash
kubectl --context cloaksync-test apply -k deployment/k8s/test/cloaksync
kubectl --context cloaksync-test -n cloaksync-test logs -f deploy/cloaksync-test
```

The configuration is in [cloaksync.env](../deployment/k8s/test/cloaksync/cloaksync.env). It contains only test values that match the realm import. CloakSync connects to Keycloak over plain HTTP through the Service in the cluster. After the first run `kubectl --context cloaksync-test get namespaces` shows a namespace for each user who gets one.

CloakSync reads its configuration only when the pod starts. The ConfigMap keeps its name when cloaksync.env changes, so an apply does not restart the pod. After you change the configuration, apply and then restart CloakSync:

```bash
kubectl --context cloaksync-test -n cloaksync-test rollout restart deploy/cloaksync-test
```

## Reset

The test environment keeps its state in two places. Keycloak keeps its users, groups and roles inside its container, so a new Keycloak pod imports the realm again. The namespaces, roles and role bindings that CloakSync creates are objects in the cluster. They stay when the pods restart and when minikube stops. Only a delete removes them.

### Reset Keycloak and the Namespaces

These steps put the cluster back to the state before the first run of CloakSync. CloakSync stops first, so it cannot create the namespaces again during the reset. It stays stopped after the reset. To start it again, follow [Deploy CloakSync](#deploy-cloaksync). The manifest sets one replica, so the apply starts the pod again, and its log shows a first run.

```bash
kubectl --context cloaksync-test -n cloaksync-test scale deploy/cloaksync-test --replicas=0
kubectl --context cloaksync-test -n cloaksync-test wait --for=delete pod -l app.kubernetes.io/name=cloaksync --timeout=60s
kubectl --context cloaksync-test delete namespace alice bob carol dave --ignore-not-found
kubectl --context cloaksync-test -n keycloak-test rollout restart deploy/keycloak
kubectl --context cloaksync-test -n keycloak-test rollout status deploy/keycloak
```

CloakSync ignores the stop signal, so its pod stops only when Kubernetes kills it after 30 seconds. The wait makes sure that it cannot create the namespaces again after the delete. The delete of a namespace also deletes the roles and role bindings in it. kubectl waits until the namespaces are gone.

The reset is a temporary solution. The delete lists the namespaces by hand. The list must match the test users in [realm-cluster.json](../deployment/k8s/test/keycloak/realm-cluster.json) who get a namespace. When you add or remove such a user, change the list too.

### Remove the Cluster

```bash
minikube delete -p cloaksync-test
```

After that, start again at [Setup](#setup).

## Test Users

The realm has one test user for each way a user can get a namespace, and one who gets none:

| User  | Group                     | Tests                                                         | Namespace |
|-------|---------------------------|---------------------------------------------------------------|-----------|
| alice | `k8s-users`               | direct member of the group `CS_KCK_GROUP_UUID`                | yes       |
| bob   | `k8s-users/k8s-users-sub` | member of a subgroup                                          | yes       |
| carol | `k8s-role-group`          | member of a group with the realm role `CS_KCK_ROLE_NAME`      | yes       |
| dave  | `no-access`               | in neither                                                    | no        |

The group `k8s-users` has a fixed UUID in the import, so `CS_KCK_GROUP_UUID` stays valid after each import. The user `service-account-admin-cli` is not a test user. Keycloak creates it for the client `admin-cli`, and CloakSync logs in as it.

## Login Through OIDC Is Not Set up Yet

The test environment does not yet support kubectl login through Keycloak. CloakSync does not need it, but a test of the login itself does.

The problem is the address of Keycloak. For a login, three parties must reach Keycloak at the same URL. The browser on your machine opens the login page. kubectl gets the token. The API server inside minikube fetches the public keys of Keycloak to check the token. The `iss` claim of the token contains the URL of Keycloak. The API server accepts a token only if this URL is exactly the URL in its configuration. Now Keycloak has only an address inside the cluster, which the browser cannot reach.

The API server also accepts only an HTTPS URL for Keycloak. Kubernetes has no setting that allows plain HTTP, because the API server gets the keys that it trusts from this URL. Over HTTP someone in between could replace them.

To set up the login:

1. Give Keycloak a hostname that the browser and the API server can both resolve. One way is the minikube ingress addon with a nip.io name such as `keycloak.192.168.49.2.nip.io`.
2. Make a self-signed CA and a certificate for this hostname. Keycloak serves HTTPS with the certificate. The API server and kubelogin trust the CA. For the API server this is `--oidc-ca-file`.
3. Start minikube with the OIDC flags of the API server as `--extra-config=apiserver.oidc-...`.
4. Add a client `apiserver` to the realm for kubelogin.

On macOS with the Docker driver the minikube IP is not reachable from the host. Step 1 then needs `minikube tunnel` or a port-forward.

## Decisions

### Minikube Runs with the Docker Driver

Minikube runs the cluster in a Docker container.

The test environment must run on Linux and macOS at the minimum. The Docker driver works on both. The `none` driver runs the Kubernetes components directly on the host, but it is available only on Linux.

We use Docker Desktop because it is available on Linux and macOS. On Linux, minikube recommends Docker Engine and shows a warning for Docker Desktop. The warning does not stop the setup.

### Versions Match Production

The test environment uses the same Kubernetes and Keycloak versions as production, so that an upgrade test starts from the real state.

Production runs Kubernetes v1.35.7 on the API server and v1.35.7 or v1.35.9 on the nodes. The test environment uses v1.35.7. To check the production version:

```bash
kubectl --context <prod-context> version
kubectl --context <prod-context> get nodes -o wide
```

The first command shows the API server version in the line "Server Version". The second shows the kubelet version of each node.

The test environment uses Keycloak 26.8.1 with the image `quay.io/keycloak/keycloak:26.8.1` until the production version is known.

### Commands Name Their Context

The test cluster runs as the minikube profile `cloaksync-test`. Its kube context and all its namespaces have test in their names, so a test resource is easy to tell apart from a production one.

Every kubectl command in this file names its cluster with `--context`. The flag selects the cluster for this one command only. So a command goes to the test cluster whatever the current context is. It cannot reach production by mistake.
