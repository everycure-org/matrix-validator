# MATRIX validator

A validation tool for KG edges and nodes in KGX format.

# Getting started for Developers

1. Make sure you have poetry installed
2. Run `make install` to install the poetry environment
3. Run `make test` to see if it worked

The tool is currently divided in 3 files:

- `src/matrix_validator/cli.py` contains all CLI methods (click-based) and should not contain any code other than CLI boilerplate (in particular no IO)
- `src/matrix_validator/validator.py` contains all validation core functionality. This is where most of the code will live.
- `src/matrix_validator/datamodels.py` contains the edge and nodes schemas.
- `src/matrix_validator/util.py` contains any utility methods that we might need.

# Acknowledgements

This [cookiecutter](https://cookiecutter.readthedocs.io/en/stable/README.html) project was developed from the [monarch-project-template](https://github.com/monarch-initiative/monarch-project-template) template and will be kept up-to-date using [cruft](https://cruft.github.io/cruft/).
