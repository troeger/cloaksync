# Minikube

Minikube runs a small Kubernetes cluster on one machine. We use it for the [test environment](../test-env.md).

# Profiles and Kube Contexts

A profile is minikube's own record of a cluster. It holds the settings of the cluster, such as the driver and the Kubernetes version, in `~/.minikube/profiles/<profile>/`. With the Docker driver, the cluster itself runs in a Docker container with the same name. `minikube start`, `stop` and `delete` act on the profile that `-p` names.

A kube context is an entry in the kubeconfig, usually `~/.kube/config`. It names a cluster address, the credentials for it and optionally a default namespace. kubectl and all other Kubernetes tools read the kubeconfig.

`minikube start -p <profile>` connects the two. It adds a context with the same name as the profile to the kubeconfig, so kubectl can reach the new cluster. By default it also makes this context the current context.
