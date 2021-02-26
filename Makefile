flake8:
	flake8 pacu.py modules/ebs__download_snapshots

stubgen:
	test -d stubs || stubgen --include-private -o stubs -p boto3 -p botocore -p dsnap

mypy: stubgen
	MYPYPATH="${PWD}/stubs" mypy *.py core modules/ebs__download_snapshots

lint: flake8 mypy

clean:
	rm -rf .mypy_cache/
	rm -rf .pytest_cache/
	rm -rf out/
	rm -rf ./**/**/__pycache__/

test:
	pytest ./tests
