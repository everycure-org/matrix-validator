"""CLI for matrix-validator."""

import logging as _logging

import click

from matrix_validator import __version__

logger = _logging.getLogger(__name__)


def get_validator(validator):
    """Get the validator class."""
    if validator == "python":
        from matrix_validator.validator_purepython import ValidatorPurePythonImpl

        return ValidatorPurePythonImpl()
    elif validator == "pandera":
        from matrix_validator.validator_schema import ValidatorPanderaImpl

        return ValidatorPanderaImpl()
    elif validator == "polars":
        from matrix_validator.validator_polars import ValidatorPolarsImpl

        return ValidatorPolarsImpl()
    else:
        raise ValueError(f"Unknown validator: {validator}")


@click.group()
@click.option("-v", "--verbose", count=True)
@click.option("-q", "--quiet")
@click.version_option(__version__)
def main(verbose: int, quiet: bool):
    """Run the SSSOM CLI."""
    logger = _logging.getLogger()

    if verbose >= 2:
        logger.setLevel(level=_logging.DEBUG)
    elif verbose == 1:
        logger.setLevel(level=_logging.INFO)
    else:
        logger.setLevel(level=_logging.WARNING)
    if quiet:
        logger.setLevel(level=_logging.ERROR)


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
@click.option("--nodes", type=click.Path(), required=False, help="Path to the nodes TSV file.")
@click.option("--edges", type=click.Path(), required=False, help="Path to the edges TSV file.")
@click.option("--report-dir", type=click.Path(writable=True), required=False, help="Path to write report.")
@click.option("--validator", type=str, required=False, help="Path to write report.", default="polars")
@click.option(
    "--output-format",
    type=click.Choice(["txt", "md"], case_sensitive=False),
    default="txt",
    help="Format of the validation report.",
)
def validate(nodes, edges, report_dir, validator, output_format):
    """
    CLI for matrix-validator.

    This validates a knowledge graph using optional nodes and edges TSV files.
    """
    try:
        validator = get_validator(validator)
        if output_format:
            validator.set_output_format(output_format)
        if report_dir:
            validator.set_report_dir(report_dir)
        validator.validate(nodes, edges)
    except Exception as e:
        logger.exception(f"Error during validation: {e}")
        click.echo("Validation failed. See logs for details.", err=True)


if __name__ == "__main__":
    main()
