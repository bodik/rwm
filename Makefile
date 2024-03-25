all: lint

install:
	apt-get -y install awscli make rclone yamllint

venv:
	apt-get -y install python3-venv
	python3 -m venv venv
	venv/bin/pip install -U pip
	venv/bin/pip install -r requirements.lock

freeze:
	@pip freeze | grep -v '^pkg[-_]resources='

lint: lint-py lint-yaml

lint-py:
	python3 -m flake8 rwm.py tests
	python3 -m pylint rwm.py tests

lint-yaml:
	yamllint --strict .

test:
	python3 -m pytest -v tests/

coverage:
	coverage run --source rwm -m pytest tests/ -x -vv
	coverage report --show-missing --fail-under 100
