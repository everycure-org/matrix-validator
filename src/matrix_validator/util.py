"""Utilities for the matrix validator."""

import polars as pl


def read_tsv_as_strings(file_path):
    """Read a TSV file with all columns interpreted as strings."""
    return pl.read_csv(
        file_path,
        separator="\t",
        infer_schema_length=0,  # Avoid inferring any schema
    )
