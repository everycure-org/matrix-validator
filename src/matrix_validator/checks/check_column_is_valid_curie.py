import polars as pl

from matrix_validator.checks import CURIE_REGEX


def validate(column, file):
    violations_df = (
        pl.scan_csv(file, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select(
            [
                pl.when(~pl.col(column).str.contains(CURIE_REGEX))
                .then(pl.col(column))
                .otherwise(pl.lit(None))
                .alias(f"invalid_curie_{column}"),
            ]
        )
        .filter(pl.col(f"invalid_curie_{column}").is_not_null())
        .collect()
    )
    return violations_df.write_ndjson()
