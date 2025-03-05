"""CLI for matrix-validator."""

import logging as _logging
import sys
from functools import wraps

import click

from matrix_validator import __version__, validator_polars, validator_purepython, validator_schema

logger = _logging.getLogger(__name__)


def common_options(f):
    """Provide common click options used in various subcommands."""

    @wraps(f)
    @click.option("--nodes", type=click.Path(), required=False, help="Path to the nodes TSV file.")
    @click.option("--edges", type=click.Path(), required=False, help="Path to the edges TSV file.")
    @click.option("--limit", type=click.INT, required=False, help="Rows to validate.  When not set, all rows are validated.")
    @click.option("--report-dir", type=click.Path(writable=True), required=False, help="Path to write report.")
    @click.option(
        "--output-format",
        type=click.Choice(["txt", "md"], case_sensitive=False),
        default="txt",
        help="Format of the validation report.",
    )
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)

    return wrapper


@click.group()
@click.option("-v", "--verbose", count=True)
@click.option("-q", "--quiet")
@click.version_option(__version__)
def main(verbose: int, quiet: bool):
    """Run the Matrix Validator CLI."""
    if verbose >= 2:
        _logging.basicConfig(stream=sys.stdout, level=_logging.DEBUG)
    elif verbose == 1:
        _logging.basicConfig(stream=sys.stdout, level=_logging.INFO)
    else:
        _logging.basicConfig(stream=sys.stdout, level=_logging.WARNING)
    if quiet:
        _logging.basicConfig(stream=sys.stdout, level=_logging.ERROR)


@main.command()
@click.argument("subcommand")
@click.pass_context
def help(ctx, subcommand):
    """Echoes help for subcommands."""
    subcommand_obj = main.get_command(ctx, subcommand)
    if subcommand_obj is None:
        click.echo("The command you seek help with does not exist.")
    else:
        click.echo(subcommand_obj.get_help(ctx))


@main.command()
@common_options
def polars(nodes, edges, limit, report_dir, output_format):
    """
    CLI for matrix-validator.

    This validates a knowledge graph using optional nodes and edges TSV files.
    """
    try:
        validator = validator_polars.ValidatorPolarsImpl()
        if output_format:
            validator.set_output_format(output_format)
        if report_dir:
            validator.set_report_dir(report_dir)
        validator.validate(nodes, edges, limit)
    except Exception as e:
        logger.exception(f"Error during validation: {e}")
        click.echo("Validation failed. See logs for details.", err=True)


@main.command()
@common_options
def python(nodes, edges, limit, report_dir, output_format):
    """
    CLI for matrix-validator.

    This validates a knowledge graph using optional nodes and edges TSV files.
    """
    try:
        validator = validator_purepython.ValidatorPurePythonImpl()
        if output_format:
            validator.set_output_format(output_format)
        if report_dir:
            validator.set_report_dir(report_dir)
        validator.validate(nodes, edges, limit)
    except Exception as e:
        logger.exception(f"Error during validation: {e}")
        click.echo("Validation failed. See logs for details.", err=True)


@main.command()
@common_options
def pandera(nodes, edges, limit, report_dir, output_format):
    """
    CLI for matrix-validator.

    This validates a knowledge graph using optional nodes and edges TSV files.
    """
    try:
        validator = validator_schema.ValidatorPanderaImpl()
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
