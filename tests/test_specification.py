import pytest

from redtape.specification import (
    Action,
    DatabaseObject,
    DatabaseObjectType,
    Group,
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
    user = User(
        name="test_user_1",
        is_superuser=False,
        member_of={"a_user_group_1", "a_user_group_2"},
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
    expected = User(
        name="test_user_1",
        is_superuser=False,
        member_of={"a_user_group_1", "a_user_group_2"},
        password=Password(type=PasswordType.PLAIN, value="aplainpassword", salt=None),
        privileges={priv_1, priv_2},
    )
    user_dict = {
        "name": "test_user_1",
        "is_superuser": False,
        "member_of": {"a_user_group_1", "a_user_group_2"},
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
        Action.CREATE,
        Action.SELECT,
        Action.INSERT,
        Action.UPDATE,
        Action.DROP,
        Action.REFERENCES,
        Action.CREATE_WITH_GRANT,
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
