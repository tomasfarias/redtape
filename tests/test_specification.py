"""Unit tests for the specification module."""

from __future__ import annotations

import pytest

import redtape.connectors as db
from redtape.specification import (
    Action,
    DatabaseObject,
    DatabaseObjectType,
    Group,
    Ownerships,
    Password,
    PasswordType,
    Privilege,
    Privileges,
    Specification,
    User,
)


def test_read_from_yaml(spec_file):
    """Test a spec loads correctly from YAML file."""
    with open(spec_file) as yml_file:
        yml_str = yml_file.read()
    spec = Specification.from_yaml(yml_str)

    assert len(spec.users) == 1

    user = spec.users[0]

    assert user.is_superuser is True
    assert user.name == "test_user_1"
    assert user.member_of == {"my_user_group_1", "my_user_group_2"}

    password = Password(type=PasswordType.MD5, value="md5thisisnotanmd5hash", salt=None)

    assert user.password == password


def test_user_serialize_to_dict(spec_file):
    """Test serializing a User to a dictionary."""
    priv_1 = Privilege(
        database_object=DatabaseObject(name="one_table", type=DatabaseObjectType.TABLE),
        action=Action.SELECT,
    )
    priv_2 = Privilege(
        database_object=DatabaseObject(name="a_schema", type=DatabaseObjectType.SCHEMA),
        action=Action.CREATE,
    )
    owns_1 = DatabaseObject(
        "one_table",
        DatabaseObjectType.TABLE,
    )
    owns_2 = DatabaseObject(
        "a_schema",
        DatabaseObjectType.SCHEMA,
    )
    user = User(
        name="test_user_1",
        is_superuser=False,
        member_of={"a_user_group_1", "a_user_group_2"},
        owns=Ownerships([owns_1, owns_2]),
        password=Password(type=PasswordType.PLAIN, value="aplainpassword", salt=None),
        privileges=Privileges([priv_1, priv_2]),
    )
    expected = {
        "name": "test_user_1",
        "is_superuser": False,
        "member_of": {"a_user_group_1", "a_user_group_2"},
        "password": {
            "type": "plain",
            "value": "aplainpassword",
        },
        "owns": {
            "table": ["one_table"],
            "schema": ["a_schema"],
        },
        "privileges": {
            "table": {
                "select": [
                    "one_table",
                ],
            },
            "schema": {
                "create": [
                    "a_schema",
                ]
            },
        },
    }
    result = user.to_dict()

    assert result == expected


def test_user_deserialize_from_dict(spec_file):
    """Test deserializing a User from a dictionary."""
    priv_1 = Privilege(
        database_object=DatabaseObject(name="one_table", type=DatabaseObjectType.TABLE),
        action=Action.SELECT,
    )
    priv_2 = Privilege(
        database_object=DatabaseObject(name="a_schema", type=DatabaseObjectType.SCHEMA),
        action=Action.CREATE,
    )
    owns_1 = DatabaseObject(
        "one_table",
        DatabaseObjectType.TABLE,
    )
    owns_2 = DatabaseObject(
        "a_schema",
        DatabaseObjectType.SCHEMA,
    )
    expected = User(
        name="test_user_1",
        is_superuser=False,
        member_of={"a_user_group_1", "a_user_group_2"},
        owns=Ownerships([owns_1, owns_2]),
        password=Password(type=PasswordType.PLAIN, value="aplainpassword", salt=None),
        privileges=Privileges([priv_1, priv_2]),
    )
    user_dict = {
        "name": "test_user_1",
        "is_superuser": False,
        "member_of": {"a_user_group_1", "a_user_group_2"},
        "password": {
            "type": "plain",
            "value": "aplainpassword",
        },
        "owns": {
            "table": ["one_table"],
            "schema": ["a_schema"],
        },
        "privileges": {
            "table": {
                "select": [
                    "one_table",
                ],
            },
            "schema": {
                "create": [
                    "a_schema",
                ]
            },
        },
    }
    result = User.from_dict(user_dict)

    assert result == expected


@pytest.fixture
def specification(spec_file):
    with open(spec_file) as yml_file:
        yml_str = yml_file.read()
    spec = Specification.from_yaml(yml_str)
    return spec


def test_database_object_supported_actions():
    """Test is_action_supported evaluates actions correctly."""
    supported = [
        Action.SELECT,
        Action.INSERT,
        Action.UPDATE,
        Action.DROP,
        Action.REFERENCES,
        Action.SELECT_WITH_GRANT,
        Action.INSERT_WITH_GRANT,
        Action.UPDATE_WITH_GRANT,
        Action.DROP_WITH_GRANT,
        Action.REFERENCES_WITH_GRANT,
    ]
    for action in supported:
        assert DatabaseObject(
            name="test", type=DatabaseObjectType("TABLE")
        ).is_action_supported(action)

        assert DatabaseObject(
            name="test", type=DatabaseObjectType("VIEW")
        ).is_action_supported(action)

    supported = [
        Action.USAGE,
        Action.CREATE,
        Action.USAGE_WITH_GRANT,
        Action.CREATE_WITH_GRANT,
    ]
    for action in supported:
        assert DatabaseObject(
            name="test", type=DatabaseObjectType("SCHEMA")
        ).is_action_supported(action)

    supported = [
        Action.TEMPORARY,
        Action.CREATE,
        Action.TEMPORARY_WITH_GRANT,
        Action.CREATE_WITH_GRANT,
    ]
    for action in supported:
        assert DatabaseObject(
            name="test", type=DatabaseObjectType("DATABASE")
        ).is_action_supported(action)


def test_database_object_unsupported_actions():
    """Test is_action_supported evaluates actions correctly."""
    unsupported = [
        Action.USAGE,
        Action.EXECUTE,
        Action.TEMPORARY,
        Action.USAGE_WITH_GRANT,
        Action.EXECUTE_WITH_GRANT,
        Action.TEMPORARY_WITH_GRANT,
    ]
    for action in unsupported:
        assert not DatabaseObject(
            name="test", type=DatabaseObjectType("TABLE")
        ).is_action_supported(action)

        assert not DatabaseObject(
            name="test", type=DatabaseObjectType("VIEW")
        ).is_action_supported(action)

    unsupported = [
        Action.SELECT,
        Action.INSERT,
        Action.UPDATE,
        Action.DROP,
        Action.REFERENCES,
        Action.SELECT_WITH_GRANT,
        Action.INSERT_WITH_GRANT,
        Action.UPDATE_WITH_GRANT,
        Action.DROP_WITH_GRANT,
        Action.REFERENCES_WITH_GRANT,
    ]
    for action in unsupported:
        assert not DatabaseObject(
            name="test", type=DatabaseObjectType("SCHEMA")
        ).is_action_supported(action)


def test_group_serialize_to_dict(spec_file):
    """Test serializing a Group to a dictionary."""
    priv_1 = Privilege(
        database_object=DatabaseObject(
            name="one_schema", type=DatabaseObjectType.SCHEMA
        ),
        action=Action.USAGE,
    )
    priv_2 = Privilege(
        database_object=DatabaseObject(
            name="another_schema", type=DatabaseObjectType.SCHEMA
        ),
        action=Action.CREATE,
    )
    group = Group(
        name="test_group_1",
        privileges=Privileges([priv_1, priv_2]),
    )
    expected = {
        "name": "test_group_1",
        "privileges": {
            "schema": {
                "usage": [
                    "one_schema",
                ],
                "create": [
                    "another_schema",
                ],
            },
        },
    }
    result = group.to_dict()

    assert result == expected


def test_specification_serialize_to_dict():
    """Test serializing a Specification to a dictionary."""
    priv_1 = Privilege(
        database_object=DatabaseObject(
            name="one_schema", type=DatabaseObjectType.SCHEMA
        ),
        action=Action.USAGE,
    )
    priv_2 = Privilege(
        database_object=DatabaseObject(
            name="another_schema", type=DatabaseObjectType.SCHEMA
        ),
        action=Action.CREATE,
    )
    group = Group(
        name="test_group_1",
        privileges=Privileges([priv_1, priv_2]),
    )
    priv_1 = Privilege(
        database_object=DatabaseObject(name="one_table", type=DatabaseObjectType.TABLE),
        action=Action.SELECT,
    )
    priv_2 = Privilege(
        database_object=DatabaseObject(name="a_schema", type=DatabaseObjectType.SCHEMA),
        action=Action.CREATE,
    )
    user = User(
        name="test_user_1",
        is_superuser=False,
        member_of={"a_user_group_1", "test_group_1"},
        password=Password(type=PasswordType.PLAIN, value="aplainpassword", salt=None),
        privileges=Privileges([priv_1, priv_2]),
    )

    specification = Specification(users=[user], groups=[group])

    expected = {
        "users": [
            {
                "name": "test_user_1",
                "is_superuser": False,
                "member_of": {"a_user_group_1", "test_group_1"},
                "password": {
                    "type": "plain",
                    "value": "aplainpassword",
                },
                "privileges": {
                    "table": {
                        "select": [
                            "one_table",
                        ],
                    },
                    "schema": {
                        "create": [
                            "a_schema",
                        ]
                    },
                },
            }
        ],
        "groups": [
            {
                "name": "test_group_1",
                "privileges": {
                    "schema": {
                        "usage": [
                            "one_schema",
                        ],
                        "create": [
                            "another_schema",
                        ],
                    },
                },
            },
        ],
    }

    result = specification.to_dict()

    assert result == expected


class FakeRedshiftConnector:
    """A fake RedshiftConnector for testing."""

    def iter_tables(self):
        """Iterate over fake tables."""
        tables = [
            db.Table(
                database_name="prod",
                schema_name="public",
                table_name="users",
                table_owner="prod_admin",
                table_type="TABLE",
                table_acl="prod_admin=arwdRxtD/prod_admin,group prod_analytics=r/prod_admin",
                remarks=None,
            ),
            db.Table(
                database_name="prod",
                schema_name="public",
                table_name="sales",
                table_owner="prod_admin",
                table_type="TABLE",
                table_acl="prod_admin=arwdRxtD/prod_admin,group prod_analytics=r/prod_admin",
                remarks=None,
            ),
            db.Table(
                database_name="prod",
                schema_name="analytics",
                table_name="sales_per_user",
                table_owner="prod_analyst",
                table_type="VIEW",
                table_acl="prod_analyst=arwdRxtD/prod_admin,group analytics_consumers=r/prod_analyst",
                remarks=None,
            ),
            db.Table(
                database_name="dev",
                schema_name="dev_analytics",
                table_name="dev_table_1",
                table_owner="dev_analyst",
                table_type="TABLE",
                table_acl="dev_analyst=arwdRxtD/prod_admin",
                remarks=None,
            ),
            db.Table(
                database_name="dev",
                schema_name="dev_analytics",
                table_name="dev_table_2",
                table_owner="dev_analyst",
                table_type="TABLE",
                table_acl="dev_analyst=arwdRxtD/prod_admin",
                remarks=None,
            ),
        ]
        for table in tables:
            yield table

    def iter_schemas(self):
        """Iterate over fake schemas."""
        schemas = [
            db.Schema(
                database_name="prod",
                schema_name="public",
                schema_owner="prod_admin",
                schema_type="local",
                schema_acl="{prod_admin=UC/prod_admin,group prod_analytics=U/prod_admin}",
                source_database=None,
                schema_option=None,
            ),
            db.Schema(
                database_name="prod",
                schema_name="analytics",
                schema_owner="prod_analyst",
                schema_type="local",
                schema_acl="{prod_analyst=UC/prod_admin,group prod_analytics=UC/prod_admin}",
                source_database=None,
                schema_option=None,
            ),
            db.Schema(
                database_name="dev",
                schema_name="dev_analytics",
                schema_owner="dev_analyst",
                schema_type="local",
                schema_acl="{dev_analyst=UC/dev_analyst}",
                source_database=None,
                schema_option=None,
            ),
        ]
        for schema in schemas:
            yield schema

    def iter_databases(self):
        """Iterate over fake databases."""
        databases = [
            db.Database(
                database_name="prod",
                database_owner="prod_admin",
                database_acl="{prod_admin=CT/prod_admin,prod_analyst=T/prod_admin}",
            ),
            db.Database(
                database_name="dev",
                database_owner="dev_analyst",
                database_acl="{dev_analyst=CT/prod_admin}",
            ),
        ]
        for database in databases:
            yield database

    def iter_users(self):
        """Iterate over fake users."""
        users = [
            db.User(
                usename="prod_admin",
                usesysid=100,
                usecreatedb=True,
                usesuper=True,
                usecatupd=False,
                valuntil=None,
                useconfig=None,
            ),
            db.User(
                usename="prod_analyst",
                usesysid=101,
                usecreatedb=False,
                usesuper=False,
                usecatupd=False,
                valuntil=None,
                useconfig=None,
            ),
            db.User(
                usename="dev_analyst",
                usesysid=102,
                usecreatedb=False,
                usesuper=False,
                usecatupd=False,
                valuntil=None,
                useconfig=None,
            ),
        ]

        for user in users:
            yield user

    def iter_groups(self):
        """Iterate over fake groups."""
        groups = [
            db.Group(
                groname="prod_analytics",
                grosysid=103,
                grolist=[101],
            ),
            db.Group(
                groname="consumer_analytics",
                grosysid=104,
                grolist=[102],
            ),
            db.Group(
                groname="everyone",
                grosysid=105,
                grolist=[100, 101, 102],
            ),
        ]

        for group in groups:
            yield group


def test_specification_from_redshift_connector_users_created():
    """Test loading an specification from a RedshiftConnector."""
    connector = FakeRedshiftConnector()
    spec = Specification.from_redshift_connector(connector)

    assert len(spec.users) == 3

    users = set((user.name for user in spec.users))
    assert users == {"dev_analyst", "prod_analyst", "prod_admin"}

    superusers = [user for user in spec.users if user.is_superuser is True]
    assert len(superusers) == 1
    assert superusers[0].name == "prod_admin"


def test_specification_from_redshift_connector_user_memberships():
    """Test loading an specification from a RedshiftConnector."""
    connector = FakeRedshiftConnector()
    spec = Specification.from_redshift_connector(connector)

    for user in spec.users:
        assert user.member_of is not None and len(user.member_of) >= 1
        assert "everyone" in user.member_of, f"{user} is not part of 'everyone' group"

        if user.name == "prod_admin":
            assert len(user.member_of) == 1

        elif user.name == "prod_analyst":
            assert len(user.member_of) == 2
            assert "prod_analytics" in user.member_of

        elif user.name == "dev_analyst":
            assert len(user.member_of) == 2
            assert "consumer_analytics" in user.member_of

    assert len(spec.groups) == 3

    groups = set((group.name for group in spec.groups))
    assert groups == {"prod_analytics", "consumer_analytics", "everyone"}


def test_specification_from_redshift_connector_user_ownerships():
    """Test loading an specification from a RedshiftConnector."""
    connector = FakeRedshiftConnector()
    spec = Specification.from_redshift_connector(connector)

    for user in spec.users:
        if user.name == "prod_admin":
            should_own = (
                DatabaseObject("prod.public.users", DatabaseObjectType.TABLE),
                DatabaseObject("prod.public.sales", DatabaseObjectType.TABLE),
                DatabaseObject("prod.public", DatabaseObjectType.SCHEMA),
                DatabaseObject("prod", DatabaseObjectType.DATABASE),
            )
            assert user.owns == Ownerships(should_own)

        elif user.name == "prod_analyst":
            should_own = (
                DatabaseObject(
                    "prod.analytics.sales_per_user", DatabaseObjectType.VIEW
                ),
                DatabaseObject("prod.analytics", DatabaseObjectType.SCHEMA),
            )
            assert user.owns == Ownerships(should_own)

        elif user.name == "dev_analyst":
            should_own = (
                DatabaseObject(
                    "dev.dev_analytics.dev_table_1", DatabaseObjectType.TABLE
                ),
                DatabaseObject(
                    "dev.dev_analytics.dev_table_2", DatabaseObjectType.TABLE
                ),
                DatabaseObject("dev.dev_analytics", DatabaseObjectType.SCHEMA),
                DatabaseObject("dev", DatabaseObjectType.DATABASE),
            )
            assert user.owns == Ownerships(should_own)


def test_specification_from_redshift_connector_user_privileges():
    """Test loading an specification from a RedshiftConnector."""
    connector = FakeRedshiftConnector()
    spec = Specification.from_redshift_connector(connector)

    all_table_actions = [Action(c) for c in "arwdxD"]
    all_schema_actions = [Action(c) for c in "UC"]
    all_database_actions = [Action(c) for c in "CT"]

    for user in spec.users:
        if user.name == "prod_admin":
            should_have = []

            for table in ("prod.public.users", "prod.public.sales"):
                for action in all_table_actions:
                    priv = Privilege(
                        DatabaseObject(table, DatabaseObjectType.TABLE), action
                    )
                    should_have.append(priv)

            for action in all_schema_actions:
                priv = Privilege(
                    DatabaseObject("prod.public", DatabaseObjectType.SCHEMA), action
                )
                should_have.append(priv)

            for action in all_database_actions:
                priv = Privilege(
                    DatabaseObject("prod", DatabaseObjectType.DATABASE), action
                )
                should_have.append(priv)

            assert user.privileges == Privileges(should_have)

        elif user.name == "prod_analyst":
            should_have = []

            for action in all_table_actions:
                priv = Privilege(
                    DatabaseObject(
                        "prod.analytics.sales_per_user", DatabaseObjectType.VIEW
                    ),
                    action,
                )
                should_have.append(priv)

            for action in all_schema_actions:
                priv = Privilege(
                    DatabaseObject("prod.analytics", DatabaseObjectType.SCHEMA), action
                )
                should_have.append(priv)

            priv = Privilege(
                DatabaseObject("prod", DatabaseObjectType.DATABASE), Action("T")
            )
            should_have.append(priv)

            assert user.privileges == Privileges(should_have)

        elif user.name == "dev_analyst":
            should_have = []

            for table in (
                "dev.dev_analytics.dev_table_1",
                "dev.dev_analytics.dev_table_2",
            ):
                for action in all_table_actions:
                    priv = Privilege(
                        DatabaseObject(table, DatabaseObjectType.TABLE), action
                    )
                    should_have.append(priv)

            for action in all_schema_actions:
                priv = Privilege(
                    DatabaseObject("dev.dev_analytics", DatabaseObjectType.SCHEMA),
                    action,
                )
                should_have.append(priv)

            for action in all_database_actions:
                priv = Privilege(
                    DatabaseObject("dev", DatabaseObjectType.DATABASE), action
                )
                should_have.append(priv)

            assert user.privileges == Privileges(should_have)


def test_specification_from_redshift_connector_groups_created():
    """Test loading an specification from a RedshiftConnector."""
    connector = FakeRedshiftConnector()
    spec = Specification.from_redshift_connector(connector)

    assert len(spec.groups) == 3

    groups = set((group.name for group in spec.groups))
    assert groups == {"prod_analytics", "consumer_analytics", "everyone"}


def test_specification_from_redshift_connector_groups_privileges():
    """Test loading an specification from a RedshiftConnector."""
    connector = FakeRedshiftConnector()
    spec = Specification.from_redshift_connector(connector)

    for group in spec.groups:
        if group.name == "prod_analytics":
            should_have = []

            for table in ("prod.public.users", "prod.public.sales"):
                priv = Privilege(
                    DatabaseObject(table, DatabaseObjectType.TABLE), Action("r")
                )
                should_have.append(priv)

            priv_1 = Privilege(
                DatabaseObject("prod.public", DatabaseObjectType.SCHEMA), Action("U")
            )
            priv_2 = Privilege(
                DatabaseObject("prod.analytics", DatabaseObjectType.SCHEMA), Action("U")
            )
            priv_3 = Privilege(
                DatabaseObject("prod.analytics", DatabaseObjectType.SCHEMA), Action("C")
            )
            should_have.extend([priv_1, priv_2, priv_3])

            assert group.privileges == Privileges(should_have)

        elif group.name == "analytics_consumer":
            should_have = []
            priv = Privilege(
                DatabaseObject(
                    "prod.analytics.sales_per_user", DatabaseObjectType.VIEW
                ),
                Action("r"),
            )
            should_have.append(priv)

            assert group.privileges == Privileges(should_have)

        elif group.name == "everyone":
            assert group.privileges is None
