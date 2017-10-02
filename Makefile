wheel:
	rm -rf build
	python3 setup.py sdist bdist_wheel

upload: wheel
	twine upload dist/dovecotauth-*
