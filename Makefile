dev: .venv
	.venv/bin/pip install -r requirements-dev.txt

.venv:
	python3 -m venv .venv

wheel:
	rm -rf build
	.venv/bin/python setup.py sdist bdist_wheel

release: wheel
	.venv/bin/twine upload dist/dovecotauth-*

.PHONY: dev wheel release
