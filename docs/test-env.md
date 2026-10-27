# Test Environment

The test environment is a local Kubernetes cluster in minikube.

## Setup

### Prerequisites

Docker and minikube.

### Start the Cluster

```bash
minikube start -p cloaksync-test --keep-context --driver=docker --kubernetes-version=v1.35.7
```

### Deploy Keycloak

```bash
kubectl --context cloaksync-test apply -k deployment/k8s/test/keycloak
kubectl --context cloaksync-test -n keycloak-test rollout status deploy/keycloak
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
