# Kustomize

Kustomize changes Kubernetes manifests without templates. It reads plain YAML, applies a fixed set of operations and writes plain YAML.

A directory for kustomize contains a file `kustomization.yaml`. It lists the input manifests and the changes to make to them. The usual pattern is a base with the shared manifests and overlays that build on the base. Here, deployment/k8s/base is the base, and production and test/cloaksync are overlays.

To see the result without a cluster, render the directory locally:

```bash
kubectl kustomize deployment/k8s/test/cloaksync
```

`make render-test` writes the result of both test kustomizations to the gitignored directory deployment/k8s/rendered. It leaves out production, because the rendered ConfigMap would contain the values of the .env file.

# Relevant Fields

Use the local rendering command (above) to see the actual effect on the manifests that this repo uses. Below gives a quick overview of some of the important fields that we use.

## Images

Changes the container images in all resources. In the overlays it finds every container with the image troeger/cloaksync and sets the tag. So the base has no tag, and each overlay selects its version. The field can also set a new image name or a digest.

## Namespace

Sets the namespace of every resource that belongs to a namespace. It also renames Namespace objects and updates the namespace of ServiceAccounts in the subjects of RoleBindings and ClusterRoleBindings. So in the test overlay, the Namespace of the base becomes cloaksync-test, and the ClusterRoleBinding points to the default ServiceAccount in cloaksync-test. Cluster-wide resources such as a ClusterRole get no namespace.

## nameSuffix and namePrefix

Add text to the name of every resource, including cluster-wide ones. Kustomize also updates the references to these names, for example the roleRef of a binding and the ConfigMap reference of a Deployment. It knows which fields of which kinds contain a reference. It changes only the names of resources it builds. A reference to something outside, such as the default ServiceAccount, stays the same. Labels also stay the same.

## configMapGenerator

Creates a ConfigMap that is in no input file. With `envs`, each `KEY=value` line of a file becomes one entry. With `files`, each file becomes one entry, with the file name as key and the content as value.

The Deployment then decides how the container gets the ConfigMap. This repo uses both ways.

CloakSync gets its config as environment variables. The overlay turns the env file into a ConfigMap with one key per variable. The Deployment of the base references this ConfigMap with `envFrom`, and Kubernetes makes each key an environment variable of the container. CloakSync reads them with `os.getenv`. No env file exists in the container. The env file is only the input format, and the same file also works for a local run.

The Keycloak of the test environment gets its realm as a file. Only the test environment deploys Keycloak. The production Keycloak runs on its own and is not part of this repo. The ConfigMap has one key, realm-cluster.json, with the whole JSON as value. The Deployment mounts the ConfigMap as a volume at /opt/keycloak/data/import, so the key becomes a file there. With `--import-realm`, Keycloak reads this file at startup and creates the realm with its users, groups and roles in its database.

`behavior` controls what happens when a ConfigMap with the same name already comes from the resources. `create` is the default and fails in that case. `merge` adds the new keys and `replace` overwrites the ConfigMap.

## generatorOptions

By default, kustomize adds a hash of the content to the name of a generated ConfigMap and updates all references to it. When the content changes, the name changes too. The pod template of the Deployment then changes, so Kubernetes starts new pods with the new config. The Keycloak test setup uses this for the realm import.

`disableNameSuffixHash: true` keeps the name fixed. The CloakSync overlays use it. A change of the env file then does not restart the pod, so it needs a `kubectl rollout restart` after the apply.

# Sources

- <https://kustomize.io/>
- <https://kubectl.docs.kubernetes.io/references/kustomize/kustomization/>
