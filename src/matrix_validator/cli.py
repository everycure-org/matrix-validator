"""CLI for matrix-validator."""

import logging as _logging
import sys

import click

from matrix_validator import __version__, validator_polars, validator_purepython, validator_schema

logger = _logging.getLogger(__name__)


@click.command()
@click.option(
    "--validator",
    type=click.Choice(["pandas", "python", "polars"], case_sensitive=False),
    default="polars",
    help="Pick validator implementation.",
)
@click.option("-c", "--config", type=click.Path(), required=False, help="Path to the config file.")
@click.option("-n", "--nodes", type=click.Path(), required=False, help="Path to the nodes TSV file.")
@click.option("-e", "--edges", type=click.Path(), required=False, help="Path to the edges TSV file.")
@click.option("-l", "--limit", type=click.INT, required=False, help="Rows to validate.  When not set, all rows are validated.")
@click.option("-r", "--report-dir", type=click.Path(writable=True), required=False, help="Path to write report.")
@click.option(
    "--output-format",
    type=click.Choice(["txt", "md"], case_sensitive=False),
    default="txt",
    help="Format of the validation report.",
)
@click.option("-v", "--verbose", count=True)
@click.option("-q", "--quiet")
@click.version_option(__version__)
def main(validator, config, nodes, edges, limit, report_dir, output_format, verbose: int, quiet: bool):
    """Run the Matrix Validator CLI."""
    if verbose >= 2:
        _logging.basicConfig(stream=sys.stdout, level=_logging.DEBUG)
    elif verbose == 1:
        _logging.basicConfig(stream=sys.stdout, level=_logging.INFO)
    else:
        _logging.basicConfig(stream=sys.stdout, level=_logging.WARNING)
    if quiet:
        _logging.basicConfig(stream=sys.stdout, level=_logging.ERROR)

    match validator:
        case "python":
            python(config, nodes, edges, limit, report_dir, output_format)
        case "pandera":
            pandera(config, nodes, edges, limit, report_dir, output_format)
        case "polars":
            polars(config, nodes, edges, limit, report_dir, output_format)


def polars(config, nodes, edges, limit, report_dir, output_format):
    """
    CLI for matrix-validator.

    This validates a knowledge graph using optional nodes and edges TSV files.
    """
    try:
        validator = validator_polars.ValidatorPolarsImpl(config)
        if output_format:
            validator.set_output_format(output_format)
        if report_dir:
            validator.set_report_dir(report_dir)
        validator.validate(nodes, edges, limit)
    except Exception as e:
        logger.exception(f"Error during validation: {e}")
        click.echo("Validation failed. See logs for details.", err=True)


def python(config, nodes, edges, limit, report_dir, output_format):
    """
    CLI for matrix-validator.

    This validates a knowledge graph using optional nodes and edges TSV files.
    """
    try:
        validator = validator_purepython.ValidatorPurePythonImpl(config)
        if output_format:
            validator.set_output_format(output_format)
        if report_dir:
            validator.set_report_dir(report_dir)
        validator.validate(nodes, edges, limit)
    except Exception as e:
        logger.exception(f"Error during validation: {e}")
        click.echo("Validation failed. See logs for details.", err=True)


def pandera(config, nodes, edges, limit, report_dir, output_format):
    """
    CLI for matrix-validator.

    This validates a knowledge graph using optional nodes and edges TSV files.
    """
    try:
        validator = validator_schema.ValidatorPanderaImpl(config)
        if output_format:
            validator.set_output_format(output_format)
        if report_dir:
            validator.set_report_dir(report_dir)
        validator.validate(nodes, edges, limit)
    except Exception as e:
        logger.exception(f"Error during validation: {e}")
        click.echo("Validation failed. See logs for details.", err=True)


if __name__ == "__main__":
    main()
