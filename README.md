# devsuite-python
Monorepo containing Python development tooling and documentation for Secretarium

## Building and Releasing Secretarium Python packages

The build process is executed from the root of each package as follows:
```sh
python -m build
```
Release is done with Twine as such :

```sh
python -m twine upload .\dist\`package_name`-`package_version`.tar.gz .\dist\`package_name`-`package_version`-py3-none-any.whl
```
