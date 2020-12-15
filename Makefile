flake8:
	flake8 pacu.py

stubgen:
	test -d stubs || stubgen --include-private -p boto3 -p botocore -o stubs

mypy: stubgen
	export MYPYPATH="${PWD}/stubs" && mypy *.py core

lint: flake8 mypy

clean:
	rm -rf .mypy_cache/
	rm -rf .pytest_cache/
	rm -rf out/
	rm -rf ./**/**/__pycache__/

test:
	pytest ./tests

graphs:
	mkdir -p out
	cd out && pyreverse -S -f ALL -o dot ../pacu.py ../core
	docker run -it  -v "${PWD}:/dot" -w /dot dotviz  -Tpng out/classes.dot -o out/classes.png
