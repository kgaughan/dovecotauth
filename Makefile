dev: .venv
	.venv/bin/pip install flit
	.venv/bin/flit install --symlink

.venv:
	python3 -m venv .venv

wheel:
	.venv/bin/flit build

release: wheel
	.venv/bin/flit publish

.PHONY: dev wheel release
