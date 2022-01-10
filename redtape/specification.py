"""Specification models.

This module contains all specification models to be loaded from a specification
file or a database connector. The core of Redtape is essentially deserializing
both the specification file and the current specification as given by a
database connector into the same models. This way, they may be compared to
prepare the queries that need to be run."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from itertools import groupby
from typing import Any, Generator, Optional, Union

from mashumaro import (
    DataClassDictMixin,
    DataClassJSONMixin,
    DataClassYAMLMixin,
    field_options,
)
from mashumaro.config import BaseConfig

from redtape.connectors import (
    REDSHIFT_GROUP_MEMBERS_QUERY,
    REDSHIFT_PRIVILEGES_QUERY,
    REDSHIFT_USERS_AND_GROUPS_QUERY,
    RedshiftConnector,
)


class BaseModel(DataClassYAMLMixin, DataClassJSONMixin, DataClassDictMixin):
    class Config(BaseConfig):
        pass


class Action(Enum):
    SELECT = "r"
    INSERT = "a"
    UPDATE = "w"
    DELETE = "d"
    DROP = "D"
    REFERENCES = "x"
    CREATE = "create"
    USAGE = "usage"
    EXECUTE = "X"
    TEMPORARY = "temporary"
    TEMP = "temp"
    RULE = "R"
    TRIGGER = "t"
    ALL = "all"

    @property
    def with_grant(self) -> bool:
        return getattr(self, "_with_grant", False)

    @with_grant.setter
    def with_grant(self, has_grant: bool):
        self._with_grant = has_grant


class DatabaseObjectType(Enum):
    TABLE = "TABLE"
    VIEW = "VIEW"
    FUNCTION = "FUNCTION"
    SCHEMA = "SCHEMA"
    DATABASE = "DATABASE"
    LANGUAGE = "LANGUAGE"
    PROCEDURE = "PROCEDURE"

    @property
    def supported_actions(self):
        if self in (DatabaseObjectType.TABLE, DatabaseObjectType.VIEW):
            return [
                Action.CREATE,
                Action.SELECT,
                Action.INSERT,
                Action.UPDATE,
                Action.DROP,
                Action.REFERENCES,
                Action.ALL,
            ]
        elif self is DatabaseObjectType.DATABASE:
            return [
                Action.CREATE,
                Action.TEMPORARY,
                Action.TEMP,
                Action.ALL,
            ]
        elif self is DatabaseObjectType.SCHEMA:
            return [
                Action.CREATE,
                Action.USAGE,
                Action.ALL,
            ]
        elif self in (DatabaseObjectType.FUNCTION, DatabaseObjectType.PROCEDURE):
            return [
                Action.EXECUTE,
                Action.ALL,
            ]
        elif self is DatabaseObjectType.LANGUAGE:
            return [
                Action.USAGE,
            ]


@dataclass(frozen=True)
class DatabaseObject(BaseModel):
    name: str
    _type: DatabaseObjectType

    def is_action_supported(self, action: Action) -> bool:
        return action in self._type.supported_actions

    def __str__(self):
        return f"<{self._type}: {self.name}>"


@dataclass(frozen=True)
class Privilege(BaseModel):
    database_object: DatabaseObject
    action: Optional[Action] = None

    def validate(self) -> tuple[bool, Optional[list[ValidationFailure]]]:
        if self.action is None:
            return True, None

        success = self.database_object.is_action_supported(self.action)
        if success is True:
            return success, None

        return success, [
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


@dataclass
class ValidationFailure:
    subject: Union[DatabaseObject, User, Group, Password]
    message: str


class PasswordType(Enum):
    PLAIN = "plain"
    SHA256 = "sha256"
    MD5 = "md5"
    DISABLED = "DISABLED"


@dataclass
class Password(BaseModel):
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

    @classmethod
    def __pre_deserialize__(cls, d: dict[Any, Any]) -> dict[Any, Any]:
        if d.get("type", None) is None:
            return d

        _type = d.pop("type")
        d["_type"] = _type

        return d

    def validate(self) -> tuple[bool, Optional[list[ValidationFailure]]]:
        failures = []
        success = True

        if self._type is PasswordType.PLAIN:
            if len(self.value) < 8 or len(self.value) > 64:
                failures.append(
                    ValidationFailure(
                        subject=self,
                        message="Password must be between 8 and 64 characters, not {len(self.value)}",
                    )
                )
                success = False

            if not any(map(str.isupper, self.value)):
                failures.append(
                    ValidationFailure(
                        subject=self,
                        message="Password must contain at least one uppercase character.",
                    )
                )
                success = False

            if not any(map(str.islower, self.value)):
                failures.append(
                    ValidationFailure(
                        subject=self,
                        message="Password must contain at least one lowercase character.",
                    )
                )
                success = False

            if not any(map(str.isdigit, self.value)):
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


@dataclass
class User(BaseModel):
    name: str
    is_superuser: bool
    password: Optional[Password] = None
    privileges: Optional[set[Privilege]] = None
    member_of: Optional[set[str]] = None

    def validate(self) -> tuple[bool, Optional[list[ValidationFailure]]]:
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

    def __post_serialize__(self, d: dict[Any, Any]) -> dict[Any, Any]:
        if d["privileges"] is None:
            d.pop("privileges")
            return d

        nested_privileges: dict[Any, Any] = {}

        def action_groupby_key(d):
            return Action(d["action"]).name.lower()

        def object_type_groupby_key(d):
            return d["database_object"]["_type"].lower()

        for object_key, object_group in groupby(
            d["privileges"], object_type_groupby_key
        ):
            privileges = nested_privileges.setdefault(object_key, {})
            for action_key, action_group in groupby(object_group, action_groupby_key):
                privileges[action_key] = [
                    p["database_object"]["name"] for p in action_group
                ]

        d["privileges"] = nested_privileges
        return d

    @classmethod
    def __pre_deserialize__(cls, d: dict[Any, Any]) -> dict[Any, Any]:
        if d.get("privileges", None) is None:
            return d

        flat_privileges = []

        for db_obj_type, v in d["privileges"].items():
            for action, db_objs in v.items():
                privilege: dict[str, Any] = {}
                privilege["action"] = Action[action.upper()]
                for db_obj in db_objs:
                    privilege["database_object"] = {
                        "_type": DatabaseObjectType[db_obj_type.upper()],
                        "name": db_obj,
                    }
                    flat_privileges.append(privilege)
        d["privileges"] = flat_privileges
        return d


@dataclass
class Group(BaseModel):
    name: str
    privileges: Optional[set[Privilege]] = None

    def validate(self) -> tuple[bool, Optional[list[ValidationFailure]]]:
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

    def __post_serialize__(self, d: dict[Any, Any]) -> dict[Any, Any]:
        if d["privileges"] is None:
            d.pop("privileges")
            return d

        nested_privileges: dict[Any, Any] = {}

        def action_groupby_key(d):
            return Action(d["action"]).name.lower()

        def object_type_groupby_key(d):
            return d["database_object"]["_type"].lower()

        for object_key, object_group in groupby(
            d["privileges"], object_type_groupby_key
        ):
            privileges = nested_privileges.setdefault(object_key, {})
            for action_key, action_group in groupby(object_group, action_groupby_key):
                privileges[action_key] = [
                    p["database_object"]["name"] for p in action_group
                ]

        d["privileges"] = nested_privileges
        return d

    @classmethod
    def __pre_deserialize__(cls, d: dict[Any, Any]) -> dict[Any, Any]:
        if d.get("privileges", None) is None:
            return d

        flat_privileges = []

        for db_obj_type, v in d["privileges"].items():
            for action, db_objs in v.items():
                privilege: dict[str, Any] = {}
                privilege["action"] = Action[action.upper()]
                for db_obj in db_objs:
                    privilege["database_object"] = {
                        "_type": DatabaseObjectType[db_obj_type.upper()],
                        "name": db_obj,
                    }
                    flat_privileges.append(privilege)
        d["privileges"] = flat_privileges
        return d


@dataclass
class Specification(BaseModel):
    users: Optional[list[User]] = None
    groups: Optional[list[Group]] = None

    @classmethod
    def from_redshift_connector(cls, connector: RedshiftConnector) -> Specification:
        """Initialize a Specification from a RedshiftConnector."""
        config: dict[str, list[Any]] = {}

        populate_users_and_groups(config, connector)
        populate_user_memberships(config, connector)
        populate_privileges(config, connector)

        return cls(users=config["users"], groups=config["groups"])

    @classmethod
    def from_yaml_file(cls, path) -> Specification:
        """Initialize a Specification from a YAML file path."""
        with open(path) as f:
            yaml_str = f.read()
        return cls.from_yaml(yaml_str)

    def group_to_users(self) -> Generator[Group, list[User], None, None]:
        for group in self.groups:
            users = [user for user in self.users if group.name in user.member_of]
            yield group, users

    def user_to_groups(self) -> Generator[User, list[Group], None, None]:
        for user in self.users:
            groups = [group for group in self.groups if group.name in user.member_of]
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
        """Check users are members of groups in this Specification.

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


def populate_users_and_groups(config: dict, connector):
    rows = connector.iter_query_rows(REDSHIFT_USERS_AND_GROUPS_QUERY)

    for row in rows:
        if row.type == "user":
            users = config.setdefault("users", [])
            users.append(
                User.from_dict(
                    {
                        "name": row.name,
                        "is_superuser": row.is_superuser,
                        "privileges": None,
                        "member_of": None,
                    }
                )
            )

        elif row.type == "group":
            groups = config.setdefault("groups", [])
            groups.append(
                Group.from_dict(
                    {
                        "name": row.name,
                        "privileges": None,
                    }
                )
            )


def populate_user_memberships(config: dict, connector):
    rows = connector.iter_query_rows(REDSHIFT_GROUP_MEMBERS_QUERY)

    user_memberships: dict[str, Any] = {}
    for row in rows:
        groups = user_memberships.setdefault(row.user_name, [])
        groups.append(row.group_name)

    for user in config["users"]:
        groups = user_memberships.get(user.name, None)
        user.member_of = groups


def populate_privileges(config: dict, connector):
    rows = connector.iter_query_rows(REDSHIFT_PRIVILEGES_QUERY)

    holder_privileges: dict[str, Any] = {}
    for row in rows:
        if row.acl is not None:
            db_obj = DatabaseObject.from_dict(
                {
                    "name": row.entity_name,
                    "_type": row.entity_type,
                }
            )

            holder_name, _, privileges_str = parse_acl(row.acl)

            with_grant = False
            for char in privileges_str:
                if char == "*":
                    with_grant = True
                    continue
                action = Action(char)
                action.with_grant = with_grant

                privilege = Privilege(
                    database_object=db_obj,
                    action=Action(action),
                )

                privileges = holder_privileges.setdefault(holder_name, [])
                privileges.append(privilege)

    for idx, user in enumerate(config["users"]):
        privileges = holder_privileges.get(user.name, None)
        config["users"][idx].privileges = privileges

    for idx, group in enumerate(config["groups"]):
        privileges = holder_privileges.get(group.name, None)
        config["groups"][idx].privileges = privileges


def parse_acl(acl: str) -> tuple[str, str, str]:
    stripped = acl.strip("{}")

    if "~" in stripped:
        acl_str, _, holder = stripped.partition("~")
    else:
        acl_str, _, holder = stripped.partition(",")

    acl_str, _, _ = acl_str.partition("/")
    user_or_group, _, privileges = acl_str.partition("=")

    if user_or_group.startswith("group"):
        holder_name = user_or_group.split(" ")[1]
        holder_type = "group"
    else:
        holder_name = user_or_group
        holder_type = "user"

    return holder_name, holder_type, privileges
