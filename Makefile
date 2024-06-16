SHELL=/bin/bash
VERSION=0.0.6

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
	cp .env deployment/k8s/production/.env
	kubectl apply -k deployment/k8s/production 
