import logging
import os

import click
import polars as pl

from matrix_validator import __version__

logger = logging.getLogger(__name__)


@click.command()
@click.option("--input", "-i", type=click.File("r"), required=True, help="Path to the edges TSV file.")
@click.option(
    "--output_dir",
    "-o",
    type=click.Path(dir_okay=True, file_okay=False, writable=True),
    required=True,
    help="Path to write report.",
)
@click.option("--verbose", "-v", count=True, help="Increase verbosity (can be repeated).")
@click.option("--quiet", "-q", is_flag=True, help="Suppress all output except errors.")
@click.version_option(__version__)
def main(input, output_dir, verbose, quiet):
    """
    CLI for matrix-validator.

    This validates a knowledge graph using optional nodes and edges TSV files.
    """
    if verbose >= 2:
        logger.setLevel(logging.DEBUG)
    elif verbose == 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.WARNING)
    if quiet:
        logger.setLevel(logging.ERROR)

    try:
        os.makedirs(output_dir, exist_ok=True)
        validate_kg_nodes(input, output_dir)
    except Exception as e:
        logger.exception(f"Error during validation: {e}")
        click.echo("Validation failed. See logs for details.", err=True)


def validate_kg_nodes(input, output_dir):
    """Validate a knowledge graph using optional nodes TSV files."""
    # Validate nodes if provided
    logger.info("Validating nodes TSV...")

    curie_regex = "^[A-Za-z_]+:.+$"
    starts_with_biolink_regex = "^biolink:.+$"

    validation_reports = (
        pl.scan_csv(input, separator="\t", truncate_ragged_lines=True, has_header=True, ignore_errors=True)
        .select(
            [
                pl.col("id").str.contains(curie_regex).sum().alias("valid_curie_id_count"),
                (~pl.col("id").str.contains(curie_regex)).sum().alias("invalid_curie_id_count"),
                pl.col("category").str.contains(starts_with_biolink_regex).sum().alias("valid_starts_with_biolink_category_count"),
                (~pl.col("category").str.contains(starts_with_biolink_regex)).sum().alias("invalid_starts_with_biolink_category_count"),
            ]
        )
        .collect()
    )

    # Write validation report
    output = os.path.join(output_dir, "edges_report.json")
    logging.info(f"Writing Validation report: {output}")
    validation_reports.write_json(output)


if __name__ == "__main__":
    main()
