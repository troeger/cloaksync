SHELL=/bin/bash
VERSION=0.0.2

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

docker:
	docker build .
