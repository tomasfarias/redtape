import pytest

from redtape.admin import GroupManagementOperation, UserManagementOperation
from redtape.specification import (
    Action,
    DatabaseObject,
    DatabaseObjectType,
    Group,
    Operation,
    Password,
    PasswordType,
    Privilege,
    User,
)


@pytest.fixture
def select_privilege():
    """Provide a select Privilege model for testing."""
    priv = Privilege(
        database_object=DatabaseObject(name="one_table", type=DatabaseObjectType.TABLE),
        action=Action.SELECT,
    )
    return priv


@pytest.fixture
def create_privilege():
    """Provide a create Privilege model for testing."""
    priv = Privilege(
        database_object=DatabaseObject(name="a_schema", type=DatabaseObjectType.SCHEMA),
        action=Action.CREATE,
    )
    return priv


@pytest.fixture
def user():
    """Provide a User model for testing."""
    user = User(
        name="test_user_1",
        is_superuser=False,
        member_of={"a_user_group_1", "a_user_group_2"},
        password=Password(type=PasswordType.PLAIN, value="aplainpassword", salt=None),
    )
    return user


@pytest.fixture
def group():
    """Provide a Group model for testing."""
    group = Group(
        name="a_user_group_1",
        privileges=None,
    )
    return group


def test_user_management_operation_create_user(user):
    """Test the build_query method for a CREATE operation."""
    op = UserManagementOperation(
        operation=Operation.CREATE,
        subject=user,
        privilege=None,
    )

    result = op.build_query()
    expected = (
        "CREATE USER test_user_1 PASSWORD 'aplainpassword';"  # pragma: allowlist secret
    )

    assert result == expected


def test_user_management_operation_drop(user):
    """Test the build_query method for a DROP operation."""
    op = UserManagementOperation(
        operation=Operation.DROP,
        subject=user,
        privilege=None,
    )

    result = op.build_query()
    expected = "DROP USER test_user_1;"

    assert result == expected


def test_user_management_operation_add_to_group(user, group):
    """Test the build_query method for an ADD_TO_GROUP operation."""
    op = UserManagementOperation(
        operation=Operation.ADD_TO_GROUP,
        subject=user,
        privilege=None,
        group=group,
    )

    result = op.build_query()
    expected = "ALTER GROUP a_user_group_1 ADD USER test_user_1;"

    assert result == expected

    op = UserManagementOperation(
        operation=Operation.ADD_TO_GROUP,
        subject=user,
        privilege=None,
    )

    with pytest.raises(TypeError):
        result = op.build_query()


def test_user_management_operation_drop_from_group(user, group):
    """Test the build_query method for a drop_from_group operation."""
    op = UserManagementOperation(
        operation=Operation.DROP_FROM_GROUP,
        subject=user,
        privilege=None,
        group=group,
    )

    result = op.build_query()
    expected = "ALTER GROUP a_user_group_1 DROP USER test_user_1;"

    assert result == expected

    op = UserManagementOperation(
        operation=Operation.ADD_TO_GROUP,
        subject=user,
        privilege=None,
    )

    with pytest.raises(TypeError):
        result = op.build_query()


def test_user_management_operation_grant(user, select_privilege, create_privilege):
    """Test the build_query method for grant operation."""
    op = UserManagementOperation(
        operation=Operation.GRANT,
        subject=user,
        privilege=select_privilege,
    )

    result = op.build_query()
    expected = "GRANT SELECT ON TABLE one_table TO test_user_1;"

    assert result == expected


def test_user_management_operation_grant_with_wildcard(user):
    """Test the build_query method for grant operation with a wildcard."""
    priv = Privilege(
        database_object=DatabaseObject(
            name="my_db.my_schema.*", type=DatabaseObjectType.TABLE
        ),
        action=Action.SELECT,
    )

    op = UserManagementOperation(
        operation=Operation.GRANT,
        subject=user,
        privilege=priv,
    )

    result = op.build_query()
    expected = "GRANT SELECT ON ALL TABLES IN SCHEMA my_db.my_schema TO test_user_1;"

    assert result == expected


def test_group_management_operation_create(group):
    """Test the build_query method for a CREATE operation."""
    op = GroupManagementOperation(
        operation=Operation.CREATE,
        subject=group,
        privilege=None,
    )

    result = op.build_query()
    expected = "CREATE GROUP a_user_group_1;"

    assert result == expected


def test_group_management_operation_drop(group):
    """Test the build_query method for a DROP operation."""
    op = GroupManagementOperation(
        operation=Operation.DROP,
        subject=group,
        privilege=None,
    )

    result = op.build_query()
    expected = "DROP GROUP a_user_group_1;"

    assert result == expected


def test_group_management_operation_grant(group, select_privilege, create_privilege):
    """Test the build_query method for grant operation."""
    op = GroupManagementOperation(
        operation=Operation.GRANT,
        subject=group,
        privilege=select_privilege,
    )

    result = op.build_query()
    expected = "GRANT SELECT ON TABLE one_table TO a_user_group_1;"

    assert result == expected


def test_group_management_operation_grant_with_wildcard(group):
    """Test the build_query method for grant operation with a wildcard."""
    priv = Privilege(
        database_object=DatabaseObject(
            name="my_db.my_schema.*", type=DatabaseObjectType.TABLE
        ),
        action=Action.SELECT,
    )

    op = GroupManagementOperation(
        operation=Operation.GRANT,
        subject=group,
        privilege=priv,
    )

    result = op.build_query()
    expected = "GRANT SELECT ON ALL TABLES IN SCHEMA my_db.my_schema TO a_user_group_1;"

    assert result == expected


def test_group_management_operation_invalid(group):
    """Test the build_query method for an invalid Group operation."""
    invalid_1 = GroupManagementOperation(
        operation=Operation.ADD_TO_GROUP,
        subject=group,
    )
    invalid_2 = GroupManagementOperation(
        operation=Operation.DROP_FROM_GROUP,
        subject=group,
    )

    with pytest.raises(ValueError):
        invalid_1.build_query()

    with pytest.raises(ValueError):
        invalid_2.build_query()
