"""Redtape's CLI."""

import sys
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Callable, Optional, Union

import typer
from rich.console import Console
from rich.progress import Progress, track
from rich.syntax import Syntax
from rich.table import Table

from redtape.admin import DatabaseAdministratorTrainer
from redtape.connectors import RedshiftConnector
from redtape.specification import (
    DatabaseObject,
    Group,
    Operation,
    Specification,
    User,
    ValidationFailure,
)

app = typer.Typer()
console = Console()

Printable = Union[str, Table, Syntax]


def console_print(message: Printable, quiet: bool):
    """Print a message if quiet is False."""
    if not quiet:
        console.print(message)


def console_status(message: str, quiet: bool, **kwargs):
    """Return a status context manager if quiet is False.

    Returns a nullcontext otherwise that does nothing. Extra
    keyword arguments arer passed on to console.status.
    """
    if not quiet:
        return console.status(message, **kwargs)
    return nullcontext()


@app.command()
def validate(
    spec_file: Optional[str] = typer.Argument(
        None,
        show_default="STDIN",
        help="A specification or a path to a file containing it.",
    ),
    quiet: bool = typer.Option(
        False,
        help="Show no output except for validation errors.",
    ),
    json: bool = typer.Option(
        False,
        help="Output validation errors as JSON.",
    ),
):
    """Validate a local specification and report any errors."""
    spec = load_spec(spec_file, quiet)
    console_print(":white_check_mark: Specification loaded!", quiet)
    success, _ = validate_spec(spec, quiet, json)

    if success is False:
        raise typer.Exit(code=1)


@app.command()
def export(
    json: bool = typer.Option(
        False,
        help="Export configuration as JSON instead of YAML.",
    ),
    dbname: Optional[str] = typer.Option(
        None,
        help="A Redshift database name to connect to.",
    ),
    host: Optional[str] = typer.Option(
        None,
        help="The host where a Redshift cluster is located.",
    ),
    port: Optional[str] = typer.Option(
        None,
        help="The port where a Redshift cluster is located.",
    ),
    user: Optional[str] = typer.Option(
        None,
        help="A user to connect to Redshift. The user should have user-management permissions.",
    ),
    password: Optional[str] = typer.Option(
        None,
        help="The passaword of the given Redshift username.",
    ),
    connection_string: Optional[str] = typer.Option(
        None,
        help="A connection string to connect to Redshift.",
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        help="The path to a INI configuration file with Redshift connection information.",
    ),
    quiet: bool = typer.Option(
        False,
        help="Show no output except for validation and/or run errors.",
    ),
):
    """Export a specification from an existing Redshift connection."""
    if connection_string is not None:
        connector = RedshiftConnector.from_dsn(connection_string)
    elif config_file is not None:
        connector = RedshiftConnector.from_ini_file(config_file)
    else:
        connector = RedshiftConnector(dbname, host, port, user, password)

    db_spec = load_spec(connector, quiet)
    with console_status("Exporting configuration...", quiet):

        if json is True:
            print_func: Callable[..., None] = console.print_json
            output: Union[str, bytes, Syntax] = db_spec.to_json()
        else:
            output = Syntax(db_spec.to_yaml(), "yaml", background_color="default")
            print_func = console.print

    print_func(output)


@app.command()
def run(
    spec_file: Optional[str] = typer.Argument(
        None,
        show_default="STDIN",
        help="A specification or a path to a file containing it.",
    ),
    dry: bool = typer.Option(
        False,
        help="Print changes but do not run them.",
    ),
    skip_validate: bool = typer.Option(
        False,
        help="Skip specification file validation.",
    ),
    user: Optional[list[str]] = typer.Option(
        None, help="Apply operations only to users named as provided."
    ),
    group: Optional[list[str]] = typer.Option(
        None, help="Apply operations only to groups named as provided."
    ),
    operation: Optional[list[Operation]] = typer.Option(
        None,
        help="Apply only provided operations.",
        case_sensitive=False,
    ),
    dbname: Optional[str] = typer.Option(
        None,
        help="A Redshift database name to connect to.",
    ),
    host: Optional[str] = typer.Option(
        None,
        help="The host where a Redshift cluster is located.",
    ),
    port: Optional[str] = typer.Option(
        None,
        help="The port where a Redshift cluster is located.",
    ),
    database_user: Optional[str] = typer.Option(
        None,
        help="A user to connect to Redshift. The user should have user-management permissions.",
    ),
    password: Optional[str] = typer.Option(
        None,
        help="The passaword of the given Redshift username.",
    ),
    connection_string: Optional[str] = typer.Option(
        None,
        help="A connection string to connect to Redshift.",
    ),
    quiet: bool = typer.Option(
        False,
        help="Show no output except of validation errors, run errors, and queries.",
    ),
):
    """Run the queries necessary to apply a specification file."""
    desired_spec = load_spec(spec_file, quiet)
    console_print(":white_check_mark: Desired specification loaded!", quiet)

    if not skip_validate:
        success, _ = validate_spec(desired_spec, quiet, False)

        if success is False:
            raise typer.Exit(code=1)

    if connection_string is not None:
        connector = RedshiftConnector.from_dsn(connection_string)
    else:
        connector = RedshiftConnector(dbname, host, port, database_user, password)

    db_spec = load_spec(connector, quiet)
    console_print(":white_check_mark: Database specification loaded!", quiet)

    builder = DatabaseAdministratorTrainer(
        desired_spec=desired_spec, current_spec=db_spec
    )

    if user is not None and len(user) > 0:

        def filter_users_with_name(u: User) -> bool:
            return u.name in user

        builder.filter_users = filter_users_with_name

    if group is not None and len(group) > 0:

        def filter_groups_with_name(g: Group) -> bool:
            return g.name in group

        builder.filter_groups = filter_groups_with_name

    if operation is not None and len(operation) > 0:
        builder.filter_operations = operation.__contains__

    with console_status(":wrench: Preparing changes...", quiet):
        admin = builder.train()

    if dry is True:
        console_print(":cactus: This is a dry-run! No queries will be run!", quiet)
        for op in admin.ops:
            query = Syntax(op.query, "sql", background_color="default")
            console_print(query, False)

        raise typer.Exit()

    with Progress(console=console) as progress:
        task = progress.add_task(
            ":factory: Running admin queries", total=len(admin.ops)
        )

        def before_callback(query, action):
            progress.console.print(f":wrench: Running: {query}")

        def progress_callback(query, action):
            progress.advance(task)

        def success_callback(query, action):
            progress.console.print(":white_check_mark: Success!")

        def on_error_callback(query, action, exc):
            progress.console.print(f":cross_mark: Query failed: {exc.pgerror}")

        success, errors = admin.manage(
            connector,
            before_callback=before_callback,
            progress_callback=progress_callback,
            success_callback=success_callback,
            on_error_callback=on_error_callback,
        )

    console_print(":ribbon: All done! :ribbon:", quiet)


def load_spec(
    spec_source: Optional[Union[str, RedshiftConnector]], quiet: bool
) -> Specification:
    """Load a specification from a given source.

    Args:
        spec_source (str, RedshiftConnector, Optional): Where to load the spec
            from. This may be a path file, a string, or a database connector.
            If None, will attempt to read from STDIN.
        quiet (bool): Omit logging when quiet is True.
    """
    if spec_source is None:
        message = ":input_latin_letters: Loading configuration from STDIN"
        spec_source = sys.stdin.read()
        loader: Callable[[Any], Specification] = Specification.from_yaml

    elif isinstance(spec_source, str):
        message = f":floppy_disk: Loading configuration from {spec_source}"
        loader = Specification.from_yaml_file

    elif isinstance(spec_source, RedshiftConnector):
        message = f":card_index: Loading configuration from {spec_source}"
        loader = Specification.from_redshift_connector

    try:
        with console_status(message, quiet):
            spec = loader(spec_source)

    except FileNotFoundError:
        console_print(
            f":cross_mark: Specification file does not exist {spec_source}", quiet
        )
        raise typer.Exit(code=1)
    except ValueError as e:
        console_print(":cross_mark: Invalid specification file", quiet)
        raise typer.Exit(code=1)
    except ConnectionError as e:
        console_print(":cross_mark: Failed to connect to Redshift Database", quiet)
        raise typer.Exit(code=1)

    return spec


def validate_spec(
    spec: Specification, quiet: bool, json: bool
) -> tuple[bool, Optional[list[ValidationFailure]]]:
    with console_status(":pencil: Validating configuration...", quiet):
        success, failures = spec.validate()

    if success is True and failures is None:
        console_print(":white_check_mark: Validation successful!", quiet)
        return True, None

    console_print(f":cross_mark: Validation encountered {len(failures)} errors!", quiet)

    if json is True:
        results = {
            "status": "fail",
            "command": "validate",
            "errors": [],
        }
        for failure in failures:
            results["errors"].append(
                {"subject": failure.subject.name, "error": failure.message}
            )

        console.print_json(data=results)

    else:
        table_results = Table(title=None)
        table_results.add_column("Subject")
        table_results.add_column("Error message")

        for failure in failures:
            table_results.add_row(failure.subject.name, failure.message)

        console_print(table_results, False)

    return success, failures


def main():
    return app()


if __name__ == "__main__":
    main()
