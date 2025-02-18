"""Main python file."""

import logging
import os.path

import click

from matrix_validator import __version__, validator

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
        validator.validate_kg_edges(input, output_dir)
    except Exception as e:
        logger.exception(f"Error during validation: {e}")
        click.echo("Validation failed. See logs for details.", err=True)


if __name__ == "__main__":
    main()
