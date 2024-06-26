all: coverage lint

install:
	apt-get -y install awscli python3-boto3 python3-pydantic python3-tabulate python3-yaml restic

install-dev:
	apt-get -y install python3-venv snapd yamllint
	python3 -m venv venv
	venv/bin/pip install -U pip
	venv/bin/pip install -r requirements.lock

freeze:
	@pip freeze | grep -v '^pkg[-_]resources='

lint: lint-py lint-yaml

lint-py:
	python3 -m flake8 rwm.py tests scripts
	python3 -m pylint rwm.py tests scripts

lint-yaml:
	yamllint --strict . examples/*.conf

test:
	# show stderr with "-o log_cli=true"
	python3 -m pytest -v tests/

coverage:
	coverage run --source rwm -m pytest tests/ -x -vv
	coverage report --show-missing --fail-under 100

microceph-service:
	snap install microceph
	snap refresh --hold microceph
	/snap/bin/microceph cluster bootstrap
	/snap/bin/microceph disk add loop,4G,3
	/snap/bin/microceph enable rgw
	while true; do /snap/bin/ceph status | grep "HEALTH_OK" && break; done
	# required for gitlab runner shell executor which runs as non-privileged user
	cp -arL /var/snap/microceph/current/conf /etc/ceph
	chmod 644 /var/snap/microceph/current/conf/*
	chmod 644 /etc/ceph/*

microceph-cleanup:
	snap remove microceph --purge
	rm -rf /etc/ceph

microceph: microceph-cleanup microceph-service

runner:
	apt-get install -y ansible
	ansible-playbook scripts/playbook_gitlab_runner.yml

docker-build:
	sh scripts/docker.sh build

docker-push:
	sh scripts/docker.sh push
