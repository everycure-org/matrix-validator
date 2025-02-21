import polars as pl

from matrix_validator.checks import DELIMITED_BY_PIPES


def validate(column, file):
    violations_df = (
        pl.scan_csv(file, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select(
            [
                pl.when(~pl.col(column).str.contains(DELIMITED_BY_PIPES))
                .then(pl.col(column))
                .otherwise(pl.lit(None))
                .alias(f"invalid_delimited_by_pipes_{column}"),
            ]
        )
        .filter(pl.col(f"invalid_delimited_by_pipes_{column}").is_not_null())
        .collect()
    )
    return violations_df.write_ndjson()
