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

At startup, Keycloak imports the realm `cluster` from [realm-cluster.json](../deployment/k8s/test/keycloak/realm-cluster.json). The admin console is at <http://localhost:8080/admin>. The user and the password are both `admin`. It is available through a port-forward:

```bash
kubectl --context cloaksync-test -n keycloak-test port-forward svc/keycloak 8080:8080
```

### Deploy CloakSync

```bash
kubectl --context cloaksync-test apply -k deployment/k8s/test/cloaksync
kubectl --context cloaksync-test -n cloaksync-test logs -f deploy/cloaksync-test
```

The configuration is in [cloaksync.env](../deployment/k8s/test/cloaksync/cloaksync.env). It contains only test values that match the realm import. CloakSync connects to Keycloak over plain HTTP through the Service in the cluster. After the first run `kubectl --context cloaksync-test get namespaces` shows a namespace for each user who gets one.

### Rebuild from Scratch

Keycloak keeps its data inside the container. A restart of the pod resets the realm to the import file:

```bash
kubectl --context cloaksync-test -n keycloak-test rollout restart deploy/keycloak
```

To remove the whole cluster:

```bash
minikube delete -p cloaksync-test
```

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
