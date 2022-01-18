"""Specification models.

This module contains all specification models to be loaded from a specification
file or a database connector. The core of Redtape is essentially deserializing
both the specification file and the current specification as given by a
database connector into the same models. This way, they may be compared to
prepare the queries that need to be run."""
from __future__ import annotations

import itertools
import operator
from enum import Enum
from typing import Any, Iterator, Optional, Union

import attrs

from redtape.connectors import Database, RedshiftConnector, Schema, Table


class Action(Enum):
    SELECT = "r"
    INSERT = "a"
    UPDATE = "w"
    DELETE = "d"
    DROP = "D"
    REFERENCES = "x"
    CREATE = "C"
    USAGE = "U"
    EXECUTE = "X"
    TEMPORARY = "T"
    RULE = "R"
    TRIGGER = "t"

    SELECT_WITH_GRANT = "r*"
    INSERT_WITH_GRANT = "a*"
    UPDATE_WITH_GRANT = "w*"
    DELETE_WITH_GRANT = "d*"
    DROP_WITH_GRANT = "D*"
    REFERENCES_WITH_GRANT = "x*"
    CREATE_WITH_GRANT = "C*"
    USAGE_WITH_GRANT = "U*"
    EXECUTE_WITH_GRANT = "X*"
    TEMPORARY_WITH_GRANT = "T*"
    RULE_WITH_GRANT = "R*"
    TRIGGER_WITH_GRANT = "t*"


class DatabaseObjectType(Enum):
    TABLE = "TABLE"
    VIEW = "VIEW"
    FUNCTION = "FUNCTION"
    SCHEMA = "SCHEMA"
    DATABASE = "DATABASE"
    LANGUAGE = "LANGUAGE"
    PROCEDURE = "PROCEDURE"

    @property
    def supported_actions(self) -> set[Action]:
        if self in (DatabaseObjectType.TABLE, DatabaseObjectType.VIEW):
            supported = {
                Action.SELECT,
                Action.INSERT,
                Action.UPDATE,
                Action.DROP,
                Action.DELETE,
                Action.REFERENCES,
                Action.CREATE_WITH_GRANT,
                Action.SELECT_WITH_GRANT,
                Action.INSERT_WITH_GRANT,
                Action.UPDATE_WITH_GRANT,
                Action.DROP_WITH_GRANT,
                Action.DELETE_WITH_GRANT,
                Action.REFERENCES_WITH_GRANT,
            }
        elif self is DatabaseObjectType.DATABASE:
            supported = {
                Action.CREATE,
                Action.TEMPORARY,
                Action.CREATE_WITH_GRANT,
                Action.TEMPORARY_WITH_GRANT,
            }
        elif self is DatabaseObjectType.SCHEMA:
            supported = {
                Action.CREATE,
                Action.USAGE,
                Action.CREATE_WITH_GRANT,
                Action.USAGE_WITH_GRANT,
            }
        elif self in (DatabaseObjectType.FUNCTION, DatabaseObjectType.PROCEDURE):
            supported = {
                Action.EXECUTE,
                Action.EXECUTE_WITH_GRANT,
            }
        elif self is DatabaseObjectType.LANGUAGE:
            supported = {
                Action.USAGE,
                Action.USAGE_WITH_GRANT,
            }
        return supported


@attrs.frozen(hash=True, slots=True)
class DatabaseObject:
    name: str
    _type: DatabaseObjectType

    def is_action_supported(self, action: Action) -> bool:
        """Check if an Action is supported by this DatabaseObject."""
        return action in self._type.supported_actions

    @classmethod
    def from_parts(cls, *args, type: DatabaseObjectType):
        name = ".".join(args)
        return cls(name, type)

    @property
    def parts(
        self,
    ) -> tuple[
        Optional[DatabaseObject], Optional[DatabaseObject], Optional[DatabaseObject]
    ]:
        """Split this object into individual DatabaseObject, if possible.

        A DatabaseObject can be split if it's name contains '.', for example:

        >>> my_obj = DatabaseObject(name="mydb.my_schema", type=DatabaseObjectType.SCHEMA)
        >>> db_obj, schema_obj, _ = my_obj.parts()
        >>> print(db_obj)
        <DatabaseObjectType.DATABASE: "mydb">
        >>> print(schema_obj)
        <DatabaseObjectType.SCHEMA: "my_schema">
        """
        parts = self.name.split(".")
        obj = DatabaseObject(
            name=parts.pop(-1),
            type=self._type,
        )
        db_obj = None
        schema_obj = None

        if len(parts) == 2:
            database, schema = parts
            db_obj = DatabaseObject(
                name=database,
                type=DatabaseObjectType.DATABASE,
            )
            schema_obj = DatabaseObject(
                name=schema,
                type=DatabaseObjectType.SCHEMA,
            )
        elif len(parts) == 1:
            (database,) = parts
            db_obj = DatabaseObject(
                name=database,
                type=DatabaseObjectType.DATABASE,
            )
            schema_obj = obj
            obj = None
        else:
            db_obj = obj
            obj = None

        return (db_obj, schema_obj, obj)

    def is_wildcard(self) -> bool:
        """Return True if this object is a wildcard."""
        return "*" == self.name

    def has_wildcard_part(self, _type: DatabaseObjectType) -> bool:
        """Return True if this object has a wildcard on a given part.

        The part is determined by the DatabaseObjectType passed. For example:
        >>> my_obj = DatabaseObject(name="mydb.my_schema.*", type=DatabaseObjectType.TABLE)
        >>> my_obj.has_wildcard_part(DatabaseObjectType.TABLE)
        True
        >>> my_obj.has_wildcard_part(DatabaseObjectType.SCHEMA)
        False
        """
        db_obj, schema_obj, obj = self.parts
        return any(
            (
                p
                for p in self.parts
                if p is not None and p._type == _type and p.is_wildcard()
            )
        )

    def __str__(self):
        return f"<{self._type}: {self.name}>"


@attrs.frozen(hash=True, slots=True)
class Privilege:
    database_object: DatabaseObject
    action: Optional[Action] = None

    def validate(self) -> tuple[bool, Optional[list[ValidationFailure]]]:
        if self.action is None:
            return True, None

        success = self.database_object.is_action_supported(self.action)
        if success is True:
            return success, None

        return False, [
            ValidationFailure(
                subject=self.database_object,
                message=f"{self.action} cannot be granted to {self.database_object}",
            )
        ]


class Operation(Enum):
    CREATE = "CREATE"
    DROP = "DROP"
    DROP_FROM_GROUP = "DROP_FROM_GROUP"
    GRANT = "GRANT"
    REVOKE = "REVOKE"
    ADD_TO_GROUP = "ADD_TO_GROUP"

    @property
    def canonical(self) -> str:
        if self is Operation.DROP_FROM_GROUP:
            return "DROP"
        elif self is Operation.ADD_TO_GROUP:
            return "ADD"
        else:
            return self.value


@attrs.frozen(hash=True)
class ValidationFailure:
    subject: Union[DatabaseObject, User, Group, Password]
    message: str


class PasswordType(Enum):
    """All supported Password types."""

    PLAIN = "plain"
    SHA256 = "sha256"
    MD5 = "md5"
    DISABLED = "DISABLED"


@attrs.define(slots=True)
class Password:
    _type: PasswordType
    value: Optional[str] = None
    salt: Optional[str] = None

    @property
    def name(self):
        return "Password"

    def __str__(self):
        if self._type is PasswordType.PLAIN:
            return self.value
        elif self._type is PasswordType.SHA256:
            return "sha256|{digest}{salt}".format(
                digest=self.value,
                salt="|{self.salt}" if self.salt is not None else "",
            )
        elif self._type is PasswordType.MD5:
            return f"md5{self.value}"
        elif self._type is PasswordType.DISABLED:
            return "DISABLED"
        else:
            raise TypeError("Password type: {self._type} is not supported.")

    def validate(self) -> tuple[bool, Optional[list[ValidationFailure]]]:
        failures = []
        success = True

        if self.value is not None and self._type is PasswordType.PLAIN:
            if len(self.value) < 8 or len(self.value) > 64:
                failures.append(
                    ValidationFailure(
                        subject=self,
                        message="Password must be between 8 and 64 characters, not {len(self.value)}",
                    )
                )
                success = False

            if any(map(str.isupper, self.value)) is False:
                failures.append(
                    ValidationFailure(
                        subject=self,
                        message="Password must contain at least one uppercase character.",
                    )
                )
                success = False

            if any(map(str.islower, self.value)) is False:
                failures.append(
                    ValidationFailure(
                        subject=self,
                        message="Password must contain at least one lowercase character.",
                    )
                )
                success = False

            if any(map(str.isdigit, self.value)) is False:
                failures.append(
                    ValidationFailure(
                        subject=self,
                        message="Password must contain at least one digit.",
                    )
                )
                success = False

        if success is True:
            return success, None
        return success, failures


class Privileges(set):
    """A set of privileges.

    Needed only to support custom serialization/deserialization.
    """


class Ownerships(set):
    """A set of DatabaseObjects owned.

    Needed only to support custom serialization/deserialization.
    """


@attrs.define(slots=True)
class Group:
    name: str
    privileges: Optional[Privileges] = None

    def __eq__(self, other) -> bool:
        if isinstance(other, str):
            return self.name == other
        elif isinstance(other, Group):
            return (self.name, self.privileges) == (other.name, other.privileges)
        else:
            return NotImplemented

    def __repr__(self):
        return f"Group(name={self.name}, privileges={self.privileges})"

    def add_privilege(self, privilege: Privilege):
        try:
            self.privileges.add(privilege)
        except AttributeError:
            self.privileges = Privileges((privilege,))

    def validate(self) -> tuple[bool, Optional[list[ValidationFailure]]]:
        if self.privileges is None:
            return True, None

        validation_failures: list[ValidationFailure] = []
        success = True

        for privilege in self.privileges:
            _, failures = privilege.validate()

            if failures is not None:
                validation_failures.extend(failures)
                success = False

        if success is True:
            return success, None
        return success, validation_failures


@attrs.define(slots=True)
class User:
    """A User in a database who can be a subject of privileges.

    Attributes:
        name (str): The user name.
        is_superuser (bool): Whether the user is a superuser or not.
        member_of (list[str]): A list of group names the user is a member of.
        password (Password): A Password associated with the user.
        privileges (Privileges): A set of Privileges associated with this user.
    """

    name: str
    is_superuser: bool
    member_of: Optional[set[str]] = None
    password: Optional[Password] = None
    privileges: Optional[Privileges] = None
    owns: Optional[Ownerships] = None

    def __eq__(self, other) -> bool:
        if isinstance(other, str):
            return self.name == other
        elif isinstance(other, User):
            return (
                self.name,
                self.privileges,
                self.is_superuser,
                self.member_of,
                self.password,
            ) == (
                other.name,
                other.privileges,
                other.is_superuser,
                other.member_of,
                other.password,
            )
        else:
            return NotImplemented

    def __repr__(self):
        return f"User(name={self.name}, privileges={self.privileges})"

    def add_privilege(self, privilege: Privilege):
        try:
            self.privileges.add(privilege)
        except AttributeError:
            self.privileges = Privileges((privilege,))

    def add_owned_db_object(self, db_obj: DatabaseObject):
        try:
            self.owns.add(db_obj)
        except AttributeError:
            self.owns = Ownerships((db_obj,))

    def validate(self) -> tuple[bool, Optional[list[ValidationFailure]]]:
        if self.privileges is None:
            return True, None

        validation_failures: list[ValidationFailure] = []
        success = True

        for privilege in self.privileges:
            _, failures = privilege.validate()

            if failures is not None:
                validation_failures.extend(failures)
                success = False

        if self.password is not None:
            _, failures = self.password.validate()

            if failures is not None:
                validation_failures.extend(failures)
                success = False

        if success is True:
            return success, None
        return success, validation_failures


@attrs.define(slots=True)
class Specification:
    users: Optional[list[User]] = None
    groups: Optional[list[Group]] = None

    @classmethod
    def from_redshift_connector(cls, connector: RedshiftConnector) -> Specification:
        """Initialize a Specification from a RedshiftConnector."""
        users, groups = cls.fetch_users_and_groups(connector)

        user_idx = {user.name: idx for idx, user in enumerate(users)}
        group_idx = {group.name: idx for idx, group in enumerate(groups)}

        public_privileges = Privileges()

        get_table_parts = operator.attrgetter(
            "database_name", "schema_name", "table_name"
        )
        get_schema_parts = operator.attrgetter("database_name", "schema_name")

        for entity in itertools.chain(
            connector.iter_tables(),
            connector.iter_schemas(),
            connector.iter_databases(),
        ):
            if isinstance(entity, Table):
                db_obj = DatabaseObject.from_parts(
                    *get_table_parts(entity),
                    type=DatabaseObjectType.TABLE,
                )
            elif isinstance(entity, Database):
                db_obj = DatabaseObject.from_parts(
                    entity.database_name,
                    type=DatabaseObjectType.DATABASE,
                )
            elif isinstance(entity, Schema):
                db_obj = DatabaseObject.from_parts(
                    *get_schema_parts(entity),
                    type=DatabaseObjectType.SCHEMA,
                )

            owner = entity.owner
            users[user_idx[owner]].add_owned_db_object(db_obj)

            for holder_name, holder_type, action in entity.iter_acl():
                action = Action(action)

                if action in (Action.TRIGGER, Action.RULE):
                    # These are not really used by Redshift.
                    # IDK why they pop up in ACLs.
                    continue

                privilege = Privilege(database_object=db_obj, action=action)

                if holder_name == "PUBLIC":
                    public_privileges.add(privilege)
                    continue

                try:
                    if holder_type == "user":
                        users[user_idx[holder_name]].add_privilege(privilege)
                    elif holder_type == "group":
                        groups[group_idx[holder_name]].add_privilege(privilege)

                except KeyError:
                    # I think this is a deleted user/group
                    continue

        if len(public_privileges) > 0:
            public_user = User(
                name="PUBLIC",
                is_superuser=False,
                privileges=public_privileges,
                owns=None,
                member_of=None,
            )
            users.append(public_user)

        return cls(users=users, groups=groups)

    @staticmethod
    def fetch_users_and_groups(
        connector: RedshiftConnector,
    ) -> tuple[list[User], list[Group]]:
        groups: list[Group] = []
        group_members: dict[int, list[str]] = {}

        for group_row in connector.iter_groups():
            group = Group(
                name=group_row.groname,
                privileges=None,
            )
            groups.append(group)

            for user_id in group_row.iter_group_members():
                user_groups = group_members.setdefault(user_id, [])
                user_groups.append(group.name)

        users: list[User] = []

        for user_row in connector.iter_users():
            user = User(
                name=user_row.usename,
                is_superuser=user_row.usesuper,
                privileges=None,
                owns=None,
                member_of=group_members.get(user_row.usesysid, None),
            )
            users.append(user)

        return users, groups

    @classmethod
    def from_yaml_file(cls, path) -> Specification:
        """Initialize a Specification from a YAML file path."""
        with open(path) as f:
            yaml_str = f.read()
        return cls.from_yaml(yaml_str)

    def group_to_users(self) -> Iterator[tuple[Group, list[User]]]:
        if self.groups is None:
            return

        for group in self.groups:
            users = [user for user in self.users if group.name in user.member_of]
            yield group, users

    def user_to_groups(self) -> Iterator[tuple[User, list[Group]]]:
        if self.users is None:
            return

        for user in self.users:
            if user.member_of is None or len(user.member_of) == 0:
                continue

            if self.groups is None:
                groups = []
            else:
                groups = [
                    group for group in self.groups if group.name in user.member_of
                ]
            yield user, groups

    def validate(self) -> tuple[bool, Optional[list[ValidationFailure]]]:
        """Validate this configuration.

        Returns:
            tuple: first value indicates whether validation was successful.
                Second value contains a list of ValidationFailures or is None
                if validation was successful.
        """
        success, failures = self.check_users_belong_to_existing_groups()

        for user in self.users:
            user_success, user_failures = user.validate()
            if user_failures is not None:
                try:
                    failures.extend(user_failures)
                except AttributeError:
                    failures = user_failures

        for group in self.groups:
            group_success, group_failures = group.validate()
            if group_failures is not None:
                try:
                    failures.extend(group_failures)
                except AttributeError:
                    failures = group_failures

        total_success = success and user_success and group_success
        return total_success, failures

    def check_users_belong_to_existing_groups(
        self,
    ) -> tuple[bool, Optional[list[ValidationFailure]]]:
        """Check Users are members of Groups in this Specification.

        Specification should contain all users and groups. Which means
        that a user cannot belong to a group that is not part of this
        Specification.

        Returns:
            tuple: first value indicates whether check was successful.
                Second value contains a list of ValidationFailures or is None
                if validation was successful.
        """
        success = True
        failures = None
        for user, groups in self.user_to_groups():
            # len mismatches would mean a group appears in member_of
            # but not in self.groups. The inverse could also be true,
            # but we are not looking to validate that as we don't know
            # which groups should a user belong to.
            if len(groups) == len(user.member_of):
                continue

            non_existing_groups = [
                group
                for group in user.member_of
                if group not in [group.name for group in groups]
            ]

            failure = ValidationFailure(
                subject=user,
                message=f"User is member of non declared groups: {non_existing_groups}",
            )
            try:
                failures.append(failure)
            except AttributeError:
                failures = [failure]

        return success, failures
