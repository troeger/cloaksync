SHELL=/bin/bash
VERSION=0.0.9

# Update version numbers, commit and tag
release-bumpversion:
	./venv/bin/bumpversion --verbose patch

push:
	git push --follow-tags

release: venv release-bumpversion push

# Checks if a virtualenv exists, and creates it in case
venv:
	test -d venv || python3 -m venv venv
	venv/bin/pip install -r deployment/requirements-dev.txt
	venv/bin/pip install -r deployment/requirements-prod.txt

run:
	venv/bin/python sync.py

docker:
	docker build . -t troeger/cloaksync

docker-run:
	docker run --env-file .env troeger/cloaksync

deploy:
	kubectl apply -k deployment/k8s/production 

# Renders the test kustomizations for review. Production is left out,
# because its ConfigMap would contain the values of its .env file.
render-test:
	mkdir -p deployment/k8s/rendered
	kubectl kustomize deployment/k8s/test/cloaksync > deployment/k8s/rendered/rendered-test-cloaksync.yaml
	kubectl kustomize deployment/k8s/test/keycloak > deployment/k8s/rendered/rendered-test-keycloak.yaml
