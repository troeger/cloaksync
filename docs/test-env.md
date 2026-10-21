# Test Environment

The test environment is a local copy of our setup in minikube. We use it to test upgrades of Keycloak to the latest version, and other changes that we do not want to try on the real cluster first.

## Setup

### Prerequisites

Docker and minikube. Each minikube release supports a range of Kubernetes versions, and `--kubernetes-version` selects one, so the minikube version does not have to match exactly.

### Start the Cluster

```bash
minikube start -p cloaksync-test --keep-context --driver=docker --kubernetes-version=v1.35.7
```

- `-p cloaksync-test` names the minikube profile. The profile name is also the name of the kube context, which the commands below use.
- `--keep-context` stops minikube from changing your current kube context.
- `--driver=docker` runs the cluster in a Docker container (see [Minikube Runs with the Docker Driver](#minikube-runs-with-the-docker-driver)).
- `--kubernetes-version` should be the production Kubernetes version (see [Versions Match Production](#versions-match-production)).

### Deploy Keycloak

```bash
kubectl --context cloaksync-test apply -k deployment/k8s/test/keycloak
kubectl --context cloaksync-test -n keycloak-test rollout status deploy/keycloak
```

At startup, Keycloak imports the realm `cluster` from [realm-cluster.json](../deployment/k8s/test/keycloak/realm-cluster.json). The admin console is available through a port-forward at <http://localhost:8080/admin>, with user `admin` and password `admin`:

```bash
kubectl --context cloaksync-test -n keycloak-test port-forward svc/keycloak 8080:8080
```

### Deploy CloakSync

```bash
kubectl --context cloaksync-test apply -k deployment/k8s/test/cloaksync
kubectl --context cloaksync-test -n cloaksync-test logs -f deploy/cloaksync-test
```

The configuration is in [cloaksync.env](../deployment/k8s/test/cloaksync/cloaksync.env). It contains only test values that match the realm import. CloakSync connects to Keycloak through the Service in the cluster, over plain HTTP. After the first run, `kubectl --context cloaksync-test get namespaces` shows a namespace for each user who gets one.

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

The test environment does not yet support `kubectl` login through Keycloak. CloakSync does not need it, but a test of the login itself does.

The problem is the address of Keycloak. For a login, three parties must reach Keycloak at the same URL. The browser on your machine opens the login page. kubectl gets the token. The API server, which runs inside minikube, fetches Keycloak's public keys to check the token. The token contains the URL of Keycloak (the `iss` claim), and the API server accepts a token only if this URL is exactly the URL it is configured with. Now Keycloak has only an address inside the cluster, which the browser cannot reach.

The API server also accepts only an HTTPS URL for Keycloak. Kubernetes has no setting that allows plain HTTP, because the API server gets the keys that it trusts from this URL. Over HTTP, someone in between could replace them.

To set up the login:

1. Give Keycloak a hostname that the browser and the API server can both resolve, for example through the minikube ingress addon and a nip.io name such as `keycloak.192.168.49.2.nip.io`.
2. Make a self-signed CA and a certificate for this hostname. Keycloak serves HTTPS with the certificate. The API server (`--oidc-ca-file`) and kubelogin trust the CA.
3. Start minikube with the OIDC flags of the API server (`--extra-config=apiserver.oidc-...`).
4. Add a client `apiserver` to the realm for kubelogin.

On macOS with the Docker driver, the minikube IP is not reachable from the host. Step 1 then needs `minikube tunnel` or a port-forward.

## Decisions

### Minikube Runs with the Docker Driver

Minikube runs the cluster in a Docker container (`--driver=docker`).

The test environment must run on Linux and macOS at the minimum. The Docker driver works on both. The `none` driver runs the Kubernetes components directly on the host, but it is available only on Linux.

We use Docker Desktop, because it is available on Linux and macOS. On Linux, minikube recommends Docker Engine and shows a warning for Docker Desktop. The warning does not stop the setup.

### Versions Match Production

The test environment uses the same Kubernetes and Keycloak versions as production, so that an upgrade test starts from the real state.

Kubernetes: production runs v1.35.7 on the API server, with nodes on v1.35.7 and v1.35.9. The test environment uses v1.35.7. To check the production version:

```bash
kubectl --context <prod-context> version
kubectl --context <prod-context> get nodes -o wide
```

`kubectl version` shows the API server version in the line "Server Version". `kubectl get nodes -o wide` shows the kubelet version of each node.

Keycloak: 26.8.1 (`quay.io/keycloak/keycloak:26.8.1`) until the production version is known.

### Commands Name Their Context

The test cluster runs as the minikube profile `cloaksync-test`. Its kube context and all its namespaces end in `test`, so a test resource is easy to tell apart from a production one.

Every kubectl command in this file names its cluster with `--context`. The flag selects the cluster for this one command only. So a command goes to the test cluster, whatever the current context is, and it cannot reach production by mistake.
