# Redtape

:ribbon: A permission management tool for AWS Redshift, with plans to extend it to other database systems. Inspired by [permifrost](https://gitlab.com/gitlab-data/permifrost/), and [pgbedrock](https://github.com/Squarespace/pgbedrock).

## Installing

### Repo

Clone this repo and install with `poetry`:

```sh
git clone git@github.com:tomasfarias/redtape.git redtape
cd redtape
poetry install
```

### PyPI

Install with `pip`:

```sh
python -m pip install redtape
```

## Usage

``` sh
❯ redtape run --help
Usage: redtape run [OPTIONS] [SPEC_FILE]

  Run the queries necessary to apply a specification file.

Arguments:
  [SPEC_FILE]  A specification or a path to a file containing it.

Options:
  --dry / --no-dry                Print changes but do not run them.
                                  [default: no-dry]
  --skip-validate / --no-skip-validate
                                  Skip specification file validation.
                                  [default: no-skip-validate]
  --user TEXT                     Apply operations only to users named as
                                  provided.
  --group TEXT                    Apply operations only to groups named as
                                  provided.
  --operation [CREATE|DROP|DROP_FROM_GROUP|GRANT|REVOKE|ADD_TO_GROUP]
                                  Apply only provided operations.
  --dbname TEXT                   A Redshift database name to connect to.
  --host TEXT                     The host where a Redshift cluster is
                                  located.
  --port TEXT                     The port where a Redshift cluster is
                                  located.
  --database-user TEXT            A user to connect to Redshift. The user
                                  should have user-management permissions.
  --password TEXT                 The passaword of the given Redshift
                                  username.
  --connection-string TEXT        A connection string to connect to Redshift.
  --quiet / --no-quiet            Show no output except of validation errors,
                                  run errors, and queries.  [default: no-
                                  quiet]
  --help                          Show this message and exit.
```

## Specification file

A YAML specification file is used to define groups, users, and their corresponding privileges.

Sample:

``` yaml
groups:
    - name: group_name
        privileges:
            table:
                select:
                    - table_name
                    - ...
                insert:
                    - table_name
                    - ...
                update:
                    - table_name
                    - ...
                drop:
                    - table_name
                    - ...
                delete:
                    - table_name
                    - ...
                references:
                    - table_name
                    - ...

            database:
                create:
                    - database_name
                    - ...
                temporary:
                    - database_name
                    - ...
                temp:
                    - database_name
                    - ...

            schema:
                create:
                    - schema_name
                    - ...
                usage:
                    - schema_name
                    - ...

            function:
                execute:
                    - function_name
                    - ...

            procedure:
                execute:
                    - function_name
                    - ...

            language:
                usage:
                    - language_name
                    - ...

users:
    - name: group_name
        is_superuser: boolean
        member_of:
            - group_name
            - ...
        password:
            type: str
            value: str
        privileges:
            table:
                select:
                    - table_name
                    - ...
                insert:
                    - table_name
                    - ...
                update:
                    - table_name
                    - ...
                drop:
                    - table_name
                    - ...
                delete:
                    - table_name
                    - ...
                references:
                    - table_name
                    - ...

            database:
                create:
                    - database_name
                    - ...
                temporary:
                    - database_name
                    - ...
                temp:
                    - database_name
                    - ...

            schema:
                create:
                    - schema_name
                    - ...
                usage:
                    - schema_name
                    - ...

            function:
                execute:
                    - function_name
                    - ...

            procedure:
                execute:
                    - function_name
                    - ...

            language:
                usage:
                    - language_name
                    - ...
```

# To do

`redtape` should be considered in Alpha status: things may break, and test coverage is low. The following tasks are planned for a 1.0.0 release:
* Increase and track test coverage.
* Documentation.
* Support for wildcard (`*`) in specifcation file.
* Support for ownership.
* Support for `ASSUMEROLE`.
* Support for `EXTERNAL` objects.
* Complete support for `mypy` static type-checking.

# License

MIT
