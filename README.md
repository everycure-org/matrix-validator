# MATRIX validator

A validation tool for KG edges and nodes in KGX format.

## Users

Install the validator:

```
pip install matrix-validator
```

Run the validator:

```
matrix-validator python \
		--report-dir tmp/ \
		--edges abc_edges.tsv \
		--nodes abc_nodes.tsv
```

Currently available options for validator are "pandera", "python" and "polars".

## Getting started for Developers

1. Make sure you have poetry installed
2. Run `make install` to install the poetry environment
3. Run `make run_small_tests` to see if it worked

The tool is currently divided in the following files (basic layout):

- `src/matrix_validator/cli.py` contains all CLI methods (click-based) and should not contain any code other than CLI boilerplate (in particular no IO)
- `src/matrix_validator/validator.py` contains the abstract validation class.
- `src/matrix_validator/datamodels.py` contains the edge and nodes schemas.
- `src/matrix_validator/util.py` contains any utility methods that we might need.
- We currently experiment with a number of different implementations:
   - `src/matrix_validator/validator_polars.py`: A very efficient pure polars implementation.
   - `src/matrix_validator/validator_purepython.py`: A pure python implementation
   - `src/matrix_validator/validator_schema.py`: A schema-based validation approach based on LinkML generated pandera schemas.

## Acknowledgements

This [cookiecutter](https://cookiecutter.readthedocs.io/en/stable/README.html) project was developed from the [monarch-project-template](https://github.com/monarch-initiative/monarch-project-template) template and will be kept up-to-date using [cruft](https://cruft.github.io/cruft/).
