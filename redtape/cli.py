"""Redtape's CLI."""

from __future__ import annotations

import os
import sys
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Callable, Optional, Union

import typer
from rich.console import Console
from rich.console import Group as ProgressGroup
from rich.live import Live
from rich.progress import Progress, track
from rich.syntax import Syntax
from rich.table import Table

from redtape.admin import DatabaseAdministratorTrainer, OnError
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
    console_print("Specification loaded!", quiet)
    success, _ = validate_spec(spec, quiet, json)

    if success is False:
        raise typer.Exit(code=1)


@app.command()
def export(
    json: bool = typer.Option(
        False,
        help="Export configuration as JSON instead of YAML.",
    ),
    config: Optional[Path] = typer.Option(
        None,
        help="Path to a Redtape configuration file for database connections. The REDSHIFT_CONFIG environment variable may be set instead.",
        case_sensitive=False,
    ),
    quiet: bool = typer.Option(
        False,
        help="Show no output except for validation and/or run errors.",
    ),
):
    """Export a specification from an existing Redshift connection."""
    if config is None:
        environ = os.environ
    else:
        environ = {"REDSHIFT_CONFIG": config}

    connector = RedshiftConnector.from_environ(environ=environ)

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
    config: Optional[Path] = typer.Option(
        None,
        help="Path to a Redtape configuration file for database connections. The REDSHIFT_CONFIG environment variable may be set instead.",
        case_sensitive=False,
    ),
    quiet: bool = typer.Option(
        False,
        help="Show no output except of validation errors, run errors, and queries.",
    ),
):
    """Run the queries necessary to apply a specification file."""
    desired_spec = load_spec(spec_file, quiet)
    console_print("Desired specification loaded!", quiet)

    if not skip_validate:
        success, _ = validate_spec(desired_spec, quiet, False)

        if success is False:
            raise typer.Exit(code=1)

    if config is None:
        environ = os.environ
    else:
        environ = {"REDSHIFT_CONFIG": config}

    connector = RedshiftConnector.from_environ(environ=environ)

    db_spec = load_spec(connector, quiet)
    console_print("Database specification loaded!", quiet)

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

    with console_status("Preparing changes...", quiet):
        admin = builder.train()

    if dry is True:
        console_print("[bold yellow]This is a dry-run! No queries will be run!", quiet)
        for op in admin.ops:
            query = Syntax(op.query, "sql", background_color="default")
            console_print(query, False)

        raise typer.Exit()

    total_queries = len([q for q in admin.queries()])

    if total_queries == 0:
        console_print("[bold red]There is nothing to do!", quiet)
        raise typer.Exit(code=1)

    main_progress = Progress(console=console)
    query_progress = Progress(console=console)

    progress_group = ProgressGroup(
        query_progress,
        main_progress,
    )

    main_task_id = main_progress.add_task("", total=total_queries)

    def before_callback(query, action):
        descr = f"Running query {idx+1} out of {total_queries}"
        main_progress.update(main_task_id, description=descr, advance=1)

        task = query_progress.add_task(f"Running: {query}", total=1)
        return task

    def success_callback(query, action, query_task):
        query_progress.update(
            query_task, description=f"[bold green]Success: {query}", advance=1
        )
        query_progress.stop_task(query_task)

    def on_error_callback(query, action, exc, query_task):
        query_progress.update(
            query_task, description=f"[bold red]Failed: {query}", advance=1
        )
        query_progress.stop_task(query_task)

    with Live(progress_group):
        success, errors = admin.manage(
            connector,
            before_callback=before_callback,
            success_callback=success_callback,
            on_error_callback=on_error_callback,
        )
        if success is True:
            main_progress.update(
                main_task_id,
                description=f"[bold green]Success: {total_queries} queries ran, all finished!",
            )
        elif len(errors) == len(total_queries):
            main_progress.update(
                main_task_id,
                description=f"[bold red]Failure: all queries failed to run.",
            )
        else:
            main_progress.update(
                main_task_id,
                description=(
                    f"[bold yellow]Partial failure: {len(errors)} "
                    "out of {total_queries} queries failed."
                ),
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
        message = "Loading configuration from STDIN"
        spec_source = sys.stdin.read()
        loader: Callable[[Any], Specification] = Specification.from_yaml

    elif isinstance(spec_source, str):
        message = f"Loading configuration from {spec_source}"
        loader = Specification.from_yaml_file

    elif isinstance(spec_source, RedshiftConnector):
        message = f"Loading configuration from {spec_source}"
        loader = Specification.from_redshift_connector

    try:
        with console_status(message, quiet):
            spec = loader(spec_source)

    except FileNotFoundError:
        console_print(
            f"[bold red]Specification file does not exist {spec_source}", quiet
        )
        raise typer.Exit(code=1)
    except ValueError as e:
        console_print("[bold red]Invalid specification file", quiet)
        raise typer.Exit(code=1)
    except ConnectionError as e:
        console_print("[bold red]Failed to connect to Redshift Database", quiet)
        raise typer.Exit(code=1)

    return spec


def validate_spec(
    spec: Specification, quiet: bool, json: bool
) -> tuple[bool, Optional[list[ValidationFailure]]]:
    with console_status("Validating configuration...", quiet):
        success, failures = spec.validate()

    if success is True and failures is None:
        console_print("Validation successful!", quiet)
        return True, None

    console_print(f"Validation encountered {len(failures)} errors!", quiet)

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
