clean:
	rm -rf .mypy_cache/
	rm -rf .pytest_cache/
	rm -rf out/
	rm -rf ./**/**/__pycache__/

clean-test: ## remove test and coverage artifacts
	rm -f .coverage
	rm -fr htmlcov/
	rm -fr .pytest_cache


stubgen:
	test -d "${PWD}/stubs" || stubgen --include-private -o "${PWD}/stubs" -p boto3 -p botocore -p dsnap

mypy: stubgen
	MYPYPATH="${PWD}/stubs" mypy pacu/*.py pacu/core pacu/modules/ebs__download_snapshots

flake8:
	flake8 cli.py pacu/main.py pacu/__init__.py pacu/__main__.py pacu/modules/ebs__download_snapshots

lint: flake8 mypy

test:
	python3 -m pytest ./tests ./pacu/modules/cfn__resource_injection/cfn__resource_injection_lambda/tests
