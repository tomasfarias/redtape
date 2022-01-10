import os
from abc import abstractmethod
from collections import namedtuple
from contextlib import contextmanager
from typing import Optional

import psycopg2

REDSHIFT_USERS_AND_GROUPS_QUERY = """
SELECT
  u.usename AS "name",
  u.usesuper AS is_superuser,
  'user' AS "type"
FROM
  pg_user u
UNION ALL
SELECT
  g.groname AS "name",
  NULL AS is_superuser,
  'group' AS "type"
FROM
  pg_group g;
"""

REDSHIFT_GROUP_MEMBERS_QUERY = """
SELECT
  groname AS group_name,
  usename AS user_name
FROM
  pg_group
LEFT JOIN
  pg_user
ON
  pg_user.usesysid = ANY(pg_group.grolist);
"""

REDSHIFT_PRIVILEGES_QUERY = """
SELECT
  rs_tables.database_name::varchar(max) AS database_name,
  rs_tables.schema_name::text AS schema_name,
  rs_tables.table_name::text AS table_name,
  database_name || '.' || schema_name || '.' || table_name AS entity_name,
  rs_tables.table_type::text AS entity_type,
  rs_tables.table_acl::text AS acl
FROM
  pg_get_shared_redshift_tables()
  rs_tables(database_name text, schema_name text, table_name text, table_type text, table_acl text, remarks text)
WHERE
  schema_name <> 'pg_catalog'
  AND schema_name <> 'information_schema'
UNION ALL
SELECT
  current_database()::varchar(max) AS database_name,
  pns.nspname::text AS schema_name,
  pgc.relname::text AS table_name,
  database_name || '.' || schema_name || '.' || table_name AS entity_name,
  (
    CASE
      WHEN (pns.nspname ~~ like_escape('pg!_temp!_%'::text, '!'::text)) THEN 'LOCAL TEMPORARY'::text
      WHEN (pgc.relkind = 'r'::"char") THEN 'TABLE'::text
      WHEN (pgc.relkind = 'v'::"char") THEN 'VIEW'::text
      ELSE NULL::text
    END
  ) AS entity_type,
  array_to_string(pgc.relacl, '~'::text)::text AS acl
FROM
  pg_namespace pns
JOIN
  pg_class pgc
ON
  pgc.relnamespace = pns.oid
WHERE
  (pgc.relkind = 'r'
  OR pgc.relkind = 'v')
  AND pns.nspname <> 'pg_catalog'
  AND pns.nspname <> 'catalog_history'
  AND pns.nspname <> 'pg_toast'
  AND pns.nspname <> 'pg_internal'
  AND pns.nspname <> 'information_schema';
"""


class DatabaseConnector:
    """Generic template class to build a database connector."""

    def __init__(self):
        self._connection = None

    @property
    @abstractmethod
    def connection(self):
        raise NotImplementedError

    @abstractmethod
    def open_connection(self):
        raise NotImplementedError

    @abstractmethod
    def run_query(self, query: str):
        raise NotImplementedError


class RedshiftConnector(DatabaseConnector):
    """Concrete implementation of a DatabaseManager for Redshift."""

    def __init__(
        self,
        dbname: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self._dbname = dbname
        self._host = host
        self._port = port
        self._user = user
        self._password = password
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
    def from_json_file(cls, path):
        import json

        with open(path) as f:
            client = cls(**json.load(f))
        return client

    @classmethod
    def from_dsn(cls, dsn):
        from psycopg2.extensions import parse_dsn

        parsed = parse_dsn(dsn)
        return cls(**parsed)

    @property
    def dbname(self):
        if self._dbname is None:
            self._dbname = os.getenv("REDTAPE_DBNAME", None)
        return self._dbname

    @property
    def host(self):
        if self._host is None:
            self._host = os.getenv("REDTAPE_HOST", None)
        return self._host

    @property
    def user(self):
        if self._user is None:
            self._user = os.getenv("REDTAPE_USER", None)
        return self._user

    @property
    def password(self):
        if self._password is None:
            self._password = os.getenv("REDTAPE_PASSWORD", None)
        return self._password

    @property
    def port(self):
        if self._port is None:
            self._port = os.getenv("REDTAPE_PORT", None)
        return self._port

    @contextmanager
    def connection(self):
        if self._connection is None or self._connection.closed != 0:
            self.open_connection()
        try:
            yield self._connection

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
        except psycopg2.OperationalError:
            raise ConnectionError(f"Failed to connect with {self}")

    def iter_query_rows(self, query: str):

        with self.connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query)
                row = cursor.fetchone()

                Row = namedtuple("Row", [col.name for col in cursor.description])

                while row is not None:
                    yield Row(*row)
                    row = cursor.fetchone()
