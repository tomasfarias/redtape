import os
from abc import abstractmethod
from collections import namedtuple
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

import attrs
import psycopg2

REDSHIFT_TABLES_QUERY = """
SELECT DISTINCT
  u.database_name,
  t.schemaname AS schema_name,
  t.tablename AS table_name,
  t.tableowner AS table_owner,
  u.table_acl,
  u.table_type,
  u.remarks
FROM pg_catalog.pg_tables t
LEFT JOIN (
SELECT
  current_database()::TEXT AS database_name,
  pns.nspname::TEXT AS schema_name,
  pgc.relname::TEXT AS table_name,
  CASE
    WHEN pns.nspname ~~ like_escape('pg!_temp!_%'::text, '!'::text) THEN 'LOCAL TEMPORARY'::text
    WHEN pgc.relkind = 'r'::"char" THEN 'TABLE'::text
    WHEN pgc.relkind = 'v'::"char" THEN 'VIEW'::text
    ELSE NULL::text
  END::TEXT AS table_type,
  array_to_string(pgc.relacl, ','::text)::TEXT AS table_acl,
  d.description::TEXT AS remarks
FROM pg_namespace pns
JOIN pg_class pgc ON pgc.relnamespace = pns.oid
LEFT JOIN pg_description d ON pgc.oid = d.objoid AND d.objsubid = 0
WHERE
  (pgc.relkind = 'r'::"char" OR pgc.relkind = 'v'::"char")
  AND has_schema_privilege("current_user"()::name, pns.nspname::text, 'USAGE'::text)
  AND has_table_privilege("current_user"()::name, pgc.oid, 'SELECT'::text)
  AND pns.nspname <> 'catalog_history'::name
  AND pns.nspname <> 'pg_toast'::name
  AND pns.nspname <> 'pg_internal'::name
) u ON t.tablename::TEXT = u.table_name::TEXT
"""

REDSHIFT_SCHEMAS_QUERY = """
SELECT DISTINCT
  s.database_name,
  u.usename AS schema_owner,
  s.schema_name,
  s.schema_type,
  s.schema_acl,
  s.source_database,
  s.schema_option
FROM (
SELECT
  current_database()::VARCHAR(MAX) AS database_name,
  pgn.nspname::text AS schema_name,
  pgn.nspowner::INT AS schema_owner,
  CASE
    WHEN ((ses.eskind IS NULL))
    THEN ('local')::text
    ELSE ('external')::text
  END::TEXT AS schema_type,
  array_to_string(pgn.nspacl, (',')::text)::TEXT AS schema_acl,
  ses.databasename::TEXT AS source_database,
  ses.esoptions::TEXT AS schema_option
FROM pg_namespace AS pgn
LEFT JOIN svv_external_schemas AS ses ON pgn.nspname = ses.schemaname
WHERE
  has_schema_privilege(("current_user"())::name, (pgn.nspname)::text,  ('USAGE')::text)
  AND (pgn.nspname <> ('catalog_history')::name)
  AND (pgn.nspname <> ('pg_toast')::name)
  AND (pgn.nspname <> ('pg_internal')::name)
  AND (pgn.nspname !~~ ('pg_temp%')::text)
UNION ALL
SELECT
  (rs_schemas.database_name)::VARCHAR(MAX) AS database_name,
  (rs_schemas.schema_name)::text AS schema_name,
  rs_schemas.schema_owner::INT,
  rs_schemas.schema_type::text AS schema_type,
  (rs_schemas.schema_acl)::text AS schema_acl,
  ''::TEXT AS source_database,
  (rs_schemas.schema_option)::text AS schema_option
FROM
  pg_get_shared_redshift_schemas()
  AS rs_schemas(
    database_name varchar,
    schema_name varchar,
    schema_owner integer,
    schema_type varchar,
    schema_acl varchar,
    schema_option varchar
  )
UNION ALL
SELECT
  (rs_schemas.database_name)::text AS database_name,
  (rs_schemas.schema_name)::text AS schema_name,
  rs_schemas.schema_owner::INT,
  ('external')::text AS schema_type,
  (rs_schemas.schema_acl)::text AS schema_acl,
  (rs_schemas.source_database)::text AS source_database,
  (rs_schemas.schema_option)::text AS schema_option
FROM
  pg_get_all_external_schemas()
  AS rs_schemas(
    database_name varchar,
    schema_name varchar,
    schema_owner integer,
    schema_type varchar,
    schema_acl varchar,
    source_database varchar,
    schema_option varchar
  )
) s
LEFT JOIN pg_user u ON s.schema_owner = u.usesysid
"""

REDSHIFT_DATABASES_QUERY = """
SELECT DISTINCT
  d.database_name,
  u.usename AS database_owner,
  d.database_acl
FROM (
SELECT
  (pgd.datname)::text AS database_name,
  pgd.datdba AS database_owner,
  array_to_string(pgd.datacl, (',')::text)::TEXT AS database_acl
FROM pg_database AS pgd
WHERE
  (pgd.datname <> ('padb_harvest')::name)
  AND (pgd.datname <> ('template0')::name)
  AND (pgd.datname <> ('template1')::name)
) d
LEFT JOIN pg_user u ON d.database_owner = u.usesysid
"""


@attrs.frozen(hash=True)
class Database:
    """A Redshift Database model.

    Attributes:
        database_name (str): The name of the database.
        database_owner (str): The user name who owns the database.
        database_acl (str): The ACL string of this database.
    """

    database_name: str
    database_owner: str
    database_acl: Optional[str]

    def iter_acl(self) -> Iterator[tuple[str, str, str]]:
        """Iterate over privileges granted specified in ACL."""
        yield from parse_acl(self.database_acl)

    @property
    def name(self) -> str:
        """Return the database's name."""
        return self.database_name

    @property
    def owner(self) -> str:
        """Return the database's owner."""
        return self.database_owner

    @property
    def type(self) -> str:
        """Indicate this object is a Database."""
        return "DATABASE"


@attrs.frozen(hash=True)
class Schema:
    """A Redshift Schema model.

    Attributes:
        database_name (str): The name of the database containing the schema.
        schema_name (str): The name of the schema.
        schema_owner (str): The user name who owns the schema.
        schema_type (str): The type of the schema.
        schema_acl (str): The ACL string of this schema.
        schema_type (str): The type of the database.
        schema_option (str): Option of this schema.
    """

    database_name: str
    schema_name: str
    schema_owner: int
    schema_type: str
    schema_acl: Optional[str]
    source_database: str
    schema_option: str

    def iter_acl(self) -> Iterator[tuple[str, str, str]]:
        """Iterate over privileges granted specified in ACL."""
        yield from parse_acl(self.schema_acl)

    @property
    def name(self) -> str:
        """Return the schema's name."""
        return self.schema_name

    @property
    def owner(self) -> str:
        """Return the schema's owner."""
        return self.schema_owner

    @property
    def type(self) -> str:
        """Indicate this object is a Schema."""
        return "SCHEMA"


@attrs.frozen(hash=True)
class Table:
    """A Redshift Table model.

    Attributes:
        database_name (str): The name of the database containing the table.
        schema_name (str): The name of the schema containing the table.
        table_name (str): The name of the table.
        table_owner (str): The user name who owns the table.
        table_type (str): The type of the table.
        table_acl (str): The ACL string of this table.
        remarks (str): Remakrs of this table.
    """

    database_name: str
    schema_name: str
    table_name: str
    table_owner: str
    table_type: str
    table_acl: Optional[str]
    remarks: str

    def iter_acl(self) -> Iterator[tuple[str, str, str]]:
        """Iterate over privileges granted specified in ACL."""
        yield from parse_acl(self.table_acl)

    @property
    def name(self) -> str:
        """Return the table's name."""
        return self.table_name

    @property
    def owner(self) -> str:
        """Return the table's owner."""
        return self.table_owner

    @property
    def type(self) -> str:
        """Indicate this object is a Table."""
        return "TABLE"


def parse_acl(acl: Optional[str], sep: str = ",") -> Iterator[tuple[str, str, str]]:
    """Iterate over a Redshift ACL string.

    The ACL string is usually produced by appending the elements of an array
    with a separator, which by default we assume it's ','.

    Args:
        acl (str): The Redshift ACL string.
        sep (str): The separator used to join an ACL string.

    Yields:
        A tuple of the holder of an action, it's type ("user", or "group"),
        and the action itself.
    """
    if acl is None:
        return

    stripped = acl.strip("{}")

    acl_strs = stripped.split(sep)

    for acl_str in acl_strs:
        acl_str, _, _ = acl_str.partition("/")
        user_or_group, _, action_chars = acl_str.partition("=")

        if user_or_group is None or user_or_group == "":
            holder_name = "PUBLIC"
            holder_type = "PUBLIC"
        elif user_or_group.startswith("group"):
            holder_name = user_or_group.split(" ")[1]
            holder_type = "group"
        else:
            holder_name = user_or_group
            holder_type = "user"

        for idx, action_char in enumerate(action_chars):
            if action_char == "*":
                continue

            try:
                grant = action_chars[idx + 1]
            except IndexError:
                pass
            else:
                if grant == "*":
                    action_char += "*"

            yield holder_name, holder_type, action_char


@attrs.frozen(hash=True)
class User:
    usename: str
    usesysid: int
    usecreatedb: bool
    usesuper: bool
    usecatupd: bool
    valuntil: Optional[str]
    useconfig: Optional[str]


@attrs.frozen(hash=True)
class Group:
    groname: str
    grosysid: str
    grolist: Optional[list[int]]

    def iter_group_members(self) -> Iterator[int]:
        """Iterate over user ids that are members of this group, if any.

        Yields:
            The user id.
        """
        if self.grolist is None:
            return

        for user_id in self.grolist:
            yield user_id


class DatabaseConnector:
    """Generic template class to build a database connector."""

    def __init__(self):
        self._connection = None

    @abstractmethod
    def open_connection(self):
        raise NotImplementedError

    @abstractmethod
    def run_query(self, query: str):
        raise NotImplementedError

    @abstractmethod
    def iter_databases(self):
        raise NotImplementedError

    @abstractmethod
    def iter_schemas(self):
        raise NotImplementedError

    @abstractmethod
    def iter_tables(self):
        raise NotImplementedError


class RedshiftConnector(DatabaseConnector):
    """Concrete implementation of a DatabaseConnector for Redshift.

    Attributes:
        dbname (str): The database's name to connect to.
        host (str): The host where the Redshift Cluster is located.
        port (str): The host's port.
        user (str): The user name to connect with.
        password (str): The user name's password.
    """

    def __init__(
        self,
        dbname: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.dbname = dbname
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.load_missing_from_env()
        super().__init__()

    def __repr__(self):
        return "RedshiftConnector(dbname={dbname}, host={host}, port={port}, user={user})".format(
            dbname=self.dbname,
            host=self.host,
            port=self.port,
            user=self.user,
        )

    def __str__(self):
        return "<RedshiftConnector: {user}@{host}:{port}/{dbname}>".format(
            dbname=self.dbname,
            host=self.host,
            port=self.port,
            user=self.user,
        )

    @classmethod
    def from_ini_file(cls, path: Path, key: str = "redtape"):
        import configparser

        config = configparser.ConfigParser()
        config.read(path)

        if dsn := config[key].get("dsn", None) is not None:
            return cls.from_dsn(dsn)
        return cls(**config[key])

    @classmethod
    def from_dsn(cls, dsn):
        from psycopg2.extensions import parse_dsn

        parsed = parse_dsn(dsn)
        return cls(**parsed)

    def load_missing_from_env(self):
        for attr in ("dbname", "host", "user", "port", "password"):
            if getattr(self, attr, None) is None:
                setattr(self, attr, os.getenv(f"REDTAPE_REDSHIFT_{attr.upper()}", None))

    def run_query(self, query: str):
        """Run a query using this RedshiftConnector's connection."""
        with self.cursor() as cursor:
            cursor.execute(query)
            result = cursor.fetchone()
        return result

    def run_query_and_iter_rows(self, query: str) -> Iterator:
        """Run query and iterate over rows with this RedshiftConnector's connection."""
        with self.cursor() as cursor:
            cursor.execute(query)
            row = cursor.fetchone()

            column_names = [str(col.name) for col in cursor.description]
            Row = namedtuple("Row", column_names)

            while row is not None:
                yield Row(*row)
                row = cursor.fetchone()

    @contextmanager
    def cursor(self):
        """A context manager to handle cursors from the underlying connection."""
        cursor = self._connection.cursor()

        try:
            yield cursor
        except Exception as e:
            raise e
        finally:
            cursor.close()

    @contextmanager
    def connect(self):
        """A context manager to handle the underlying Redshift connection."""
        if self._connection is None or self._connection.closed != 0:
            self.open_connection()
        try:
            yield self

        except Exception as e:
            self._connection.rollback()
            raise e

        else:
            self._connection.commit()

        finally:
            self._connection.close()

    def open_connection(self):
        try:
            self._connection = psycopg2.connect(
                dbname=self.dbname,
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
            )
        except psycopg2.OperationalError as e:
            raise ConnectionError(f"Failed to connect with {self}") from e

    def iter_users(self, ignore_admin: bool = False) -> Iterator[User]:
        """Iterate over all users in the Redshift cluster.

        Args:
            ignore_admin (bool): Ignore the admin user (id == 1).
        """

        query = """
        SELECT
            usename,
            usesysid,
            usecreatedb,
            usesuper,
            usecatupd,
            valuntil,
            useconfig
        FROM pg_catalog.pg_user
        """

        if ignore_admin is True:
            query += "WHERE usesysid != 1"

        with self.connect() as conn:
            for row in conn.run_query_and_iter_rows(query):
                yield User(**row._asdict())

    def iter_groups(self) -> Iterator[Group]:
        """Iterate over all Groups in the Redshift cluster."""

        query = """
        SELECT
            groname,
            grosysid,
            grolist
        FROM pg_catalog.pg_group
        """

        with self.connect() as conn:
            for row in conn.run_query_and_iter_rows(query):
                yield Group(**row._asdict())

    def iter_databases(self, ignore_admin: bool = True) -> Iterator[Database]:
        """Iterate over all databases in the Redshift cluster.

        Args:
            ignore_admin (bool): Ignore databases owned by admin user (the user created
                to create the cluster).
        """

        query = REDSHIFT_DATABASES_QUERY

        if ignore_admin is True:
            query += "WHERE usesysid != 1"

        with self.connect() as conn:
            for row in conn.run_query_and_iter_rows(query):
                yield Database(**row._asdict())

    def iter_schemas(self, ignore_system: bool = True) -> Iterator[Schema]:
        """Iterate over all schemas in the Redshift cluster.


        Args:
            ignore_system (bool): Ignore system schemas pg_catalog and information_schema.
        """

        query = REDSHIFT_SCHEMAS_QUERY

        if ignore_system is True:
            query += "WHERE s.schema_name NOT IN ('information_schema', 'pg_catalog')"

        with self.connect() as conn:
            for row in conn.run_query_and_iter_rows(query):

                yield Schema(**row._asdict())

    def iter_tables(self, ignore_system: bool = True) -> Iterator[Table]:
        """Iterate over all tables in the Redshift cluster.

        Unfortunately, in order to fetch table owners we have to query all databases as
        the only system table that contains ownership information doesn't list tables from
        other databases.

        Args:
            ignore_system (bool): Ignore system schemas pg_catalog and information_schema.
        """

        query = REDSHIFT_TABLES_QUERY

        if ignore_system is True:
            query += "WHERE t.schemaname NOT IN ('information_schema', 'pg_catalog')"

        for database in self.iter_databases():

            new_connector = RedshiftConnector(
                dbname=database.database_name,
                port=self.port,
                user=self.user,
                password=self.password,
                host=self.host,
            )

            with new_connector.connect() as conn:
                for row in conn.run_query_and_iter_rows(query):
                    yield Table(**row._asdict())
