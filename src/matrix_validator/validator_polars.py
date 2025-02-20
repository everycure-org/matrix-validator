"""Polars-based validator implementation."""

from matrix_validator.validator import Validator


class ValidatorPolarsImpl(Validator):
    """Polars-based validator implementation."""

    def __init__(self):
        """Create a new instance of the polars-based validator."""
        super().__init__()

    def validate(self, nodes_file_path, edges_file_file_path):
        """Validate a knowledge graph as nodes and edges KGX TSV files."""
        pass
