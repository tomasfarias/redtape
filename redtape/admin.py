"""An administrator to prepare and apply a specification.

The Admin should be created using the AdminBuilder class which follows
the builder pattern. Clients can control which operations will the builder
prepare for the Admin using the filter arguments, or by manually directing
the builder."""
from __future__ import annotations

from abc import abstractmethod
from enum import Enum, auto
from functools import update_wrapper
from typing import Any, Callable, Iterator, Optional, Union

import psycopg2

from redtape.connectors import RedshiftConnector
from redtape.specification import (
    DatabaseObject,
    DatabaseObjectType,
    Group,
    Operation,
    Privilege,
    Specification,
    User,
)


class OperationDispatch:
    """Decorator to dispatch on operation attribute state.

    Opreations should be registered like:
    >>> od = OperationDispatch()
    >>> class Manager:
    ... @od.register(Operation.CREATE)
    ... def handle_create(self):
    ... pass

    Attributes:
        registry (dict): Map of registered operations to handler methods.
    """

    def __init__(self):
        self.registry = {}

    def __get__(self, instance, owner) -> Callable:
        """Return a handler for the operation set in instance.

        Raises:
            ValueError: If no handler has been registered for that operation.
        """
        if instance is None:
            return self

        op = getattr(instance, "operation")
        try:
            method = self.registry[op]
        except KeyError:
            raise ValueError(
                f"{instance.subject.__class__.__name__} does not support {op} operations."
            )

        return method.__get__(instance, owner)

    def register(self, operation: Operation) -> Callable:
        """Register a handler for an operation."""

        def decorator(method):
            self.registry[operation] = method
            return method

        return decorator


class ManagementOperationError(Exception):
    """Represents an error when executing a ManagementOperation."""

    def __init__(self, action: ManagementOperation):
        self.action = action
        message = f"Failed to execute: {action}"
        super().__init__(message)


class ManagementOperation:
    """An operation to manage subjects and their privileges in a database.

    ManagementOperations are executed by the DatabaseAdministrator, and define
    the build_query method to create the query representation of the
    operation.

    Attributes:
        operation (Operation): An operation like granting privileges,
            or adding a user to a group.
        subject (User, Group): The subject of an operation is the user
            or group that the operation targets: the one who will be
            granted permissions, created, or added to a group.
        privilege (Privilege, optional): For GRANT or REVOKE operations,
            the privilege to be granted or revoked to or from the subject.
    """

    def __init__(
        self,
        operation: Operation,
        subject: Union[User, Group],
        privilege: Optional[Privilege] = None,
    ):
        self.operation = operation
        self.subject = subject
        self.privilege = privilege
        self._query: Optional[str] = None

    def __str__(self):
        if self.privilege is None:
            return f"<{self.operation}: {self.subject}>"
        else:
            if self.operationt is Operation.GRANT:
                prep = "to"
            elif self.operationt is Operation.REVOKE:
                prep = "from"

            return f"<{self.operation}: {self.privilege} {prep} {self.subject}>"

    def __repr__(self):
        return (
            f"ManagementOperation(operation={self.operation}, "
            f"subject={self.subject}, privilege={self.privilege})"
        )

    @property
    def query(self) -> str:
        """The query representation of this PrivilegeOperation."""
        if self._query is None:
            self._query = self.build_query()
        return self._query


class UserManagementOperation(ManagementOperation):
    """ManagementOperations that affect Users.

    Attributes:
        group (Group, optional): For ADD_TO_GROUP or DROP_FROM_GROUP
            operations, the group to be added to or dropped from.
    """

    build_query = OperationDispatch()

    def __init__(self, *args, group: Optional[Group] = None, **kwargs):
        self.group = group
        super().__init__(*args, **kwargs)

    def __str__(self):
        if self.group is None:
            return super().__str__()
        else:
            if self.operationt is Operation.ADD_TO_GROUP:
                prep = "to"
            elif self.operationt is Operation.DROP_FROM_GROUP:
                prep = "from"

            return f"<{self.operation}: {self.privilege} {prep} {self.group}>"

    def __repr__(self):
        return (
            f"UserManagementOperation(operation={self.operation}, "
            f"subject={self.subject}, privilege={self.privilege}, "
            f"group={self.group})"
        )

    @build_query.register(Operation.CREATE)
    def build_create_query(self) -> str:
        if self.subject.password is None:
            raise TypeError(
                f"Creating a user in Redshift requires a password not {type(self.subject.password)}."
            )

        return "CREATE USER {name}{password}{is_superuser};".format(
            name=self.subject.name,
            is_superuser=" CREATEUSER" if self.subject.is_superuser is True else "",
            password=f" PASSWORD '{self.subject.password}'",
        )

    @build_query.register(Operation.DROP)
    def build_drop_query(self) -> str:
        return f"DROP USER {self.subject.name};"

    @build_query.register(Operation.GRANT)
    def build_grant_query(self) -> str:
        if self.privilege is None:
            raise TypeError(
                f"{operation} requires a Privilege but {type(privilege)} was provided."
            )

        db_obj = self.privilege.database_object
        support_on_all_query = (
            DatabaseObjectType.TABLE,
            DatabaseObjectType.VIEW,
            DatabaseObjectType.FUNCTION,
            DatabaseObjectType.PROCEDURE,
        )
        _type = (
            db_obj._type
            if db_obj._type is not DatabaseObjectType.VIEW
            else DatabaseObjectType.TABLE
        )

        if any((db_obj.has_wildcard_part(t) for t in support_on_all_query)):
            db, schema, _ = db_obj.parts
            return (
                f"GRANT {self.privilege.action.name} ON ALL "
                f"{_type.name + 'S'} IN SCHEMA "
                f"{db.name}.{schema.name} TO {self.subject.name};"
            )

        return (
            f"GRANT {self.privilege.action.name} ON "
            f"{_type.name} {self.privilege.database_object.name} TO {self.subject.name};"
        )

    @build_query.register(Operation.DROP_FROM_GROUP)
    @build_query.register(Operation.ADD_TO_GROUP)
    def build_group_queries(self) -> str:
        if self.group is None:
            raise TypeError(
                f"{self.operation} requires a Group but "
                f"{type(self.group)} was provided."
            )

        op = self.operation.canonical
        return f"ALTER GROUP {self.group.name} {op} USER {self.subject.name};"


class GroupManagementOperation(ManagementOperation):
    """ManagementOperatinos that affect Groups."""

    build_query = OperationDispatch()

    def __repr__(self):
        return (
            f"GroupManagementOperation(operation={self.operation}, "
            f"subject={self.subject}, privilege={self.privilege}, "
            f"group={self.group})"
        )

    @build_query.register(Operation.CREATE)
    def build_create_query(self) -> str:
        return f"CREATE GROUP {self.subject.name};"

    @build_query.register(Operation.DROP)
    def build_drop_query(self) -> str:
        return f"DROP GROUP {self.subject.name};"

    @build_query.register(Operation.GRANT)
    def build_grant_query(self) -> str:
        if self.privilege is None:
            raise TypeError(
                f"{operation} requires a Privilege but {type(privilege)} was provided."
            )

        db_obj = self.privilege.database_object
        support_on_all_query = (
            DatabaseObjectType.TABLE,
            DatabaseObjectType.VIEW,
            DatabaseObjectType.FUNCTION,
            DatabaseObjectType.PROCEDURE,
        )
        _type = (
            db_obj._type
            if db_obj._type is not DatabaseObjectType.VIEW
            else DatabaseObjectType.TABLE
        )

        if any((db_obj.has_wildcard_part(t) for t in support_on_all_query)):
            db, schema, _ = db_obj.parts
            return (
                f"GRANT {self.privilege.action.name} ON ALL "
                f"{_type.name + 'S'} IN SCHEMA "
                f"{db.name}.{schema.name} TO {self.subject.name};"
            )

        return (
            f"GRANT {self.privilege.action.name} ON "
            f"{_type.name} {self.privilege.database_object.name} TO {self.subject.name};"
        )


def no_filter(_: Any) -> bool:
    """Default filter does not filter anything."""
    return True


class DatabaseAdministratorTrainer:
    """A trainer for DatabaseAdministrators.

    Defines the operations that a DatabaseAdministrator will run,
    as well as the order in which they will run. The Trainer supports
    many filters to allow the client to control the training process.

    Attributes:
        desired_spec (Specification): The desired specification of users,
            groups, and their privileges. The DatabaseAdministrator will
            be trained to make the current_spec match the desired_spec.
        current_spec (Specification): The current specification of users,
            groups, and their privileges.
        filter_users (Callable): A filter function to apply to users. Should
            return True if a given User should be managed.
        filter_groups (Callable): A filter function to apply to groups. Should
            return True if a given Group should be managed.
        filter_operations (Callable): A filter function to apply to operations.
            Should return True if a given Operation should be executed.
        filter_database_objects (Callable): A filter function to apply to
            database objects. Should return True if a given DatabaseObject
            should be managed.
        filter_privileges (Callable): A filter function to apply to privileges.
            Should return True if a given Privilege should be granted or
            revoked.
    """

    def __init__(
        self,
        desired_spec: Specification,
        current_spec: Specification,
        filter_users: Callable[[User], bool] = no_filter,
        filter_groups: Callable[[Group], bool] = no_filter,
        filter_operations: Callable[[Operation], bool] = no_filter,
        filter_database_objects: Callable[[DatabaseObject], bool] = no_filter,
        filter_privileges: Callable[[Privilege], bool] = no_filter,
    ):
        self.desired = desired_spec
        self.current = current_spec

        self.filter_users = filter_users
        self.filter_groups = filter_groups
        self.filter_operations = filter_operations
        self.filter_database_objects = filter_database_objects
        self.filter_privileges = filter_privileges

        self._management_ops: list[ManagementOperation] = []
        self._desired_groups = None
        self._desired_users = None
        self._current_groups = None
        self._current_users = None

    @property
    def desired_groups(self):
        if self._desired_groups is None:
            self._desired_groups = [
                g for g in filter(self.filter_groups, self.desired.groups)
            ]
        return self._desired_groups

    @property
    def current_groups(self):
        if self._current_groups is None:
            self._current_groups = [
                g for g in filter(self.filter_groups, self.current.groups)
            ]
        return self._current_groups

    @property
    def desired_users(self):
        if self._desired_users is None:
            self._desired_users = [
                u for u in filter(self.filter_users, self.desired.users)
            ]
        return self._desired_users

    @property
    def current_users(self):
        if self._current_users is None:
            self._current_users = [
                u for u in filter(self.filter_users, self.current.users)
            ]
        return self._current_users

    def train(self) -> DatabaseAdministrator:
        if self.filter_operations(Operation.CREATE) is True:
            self.prepare_create_subjects()

        if self.filter_operations(Operation.ADD_TO_GROUP) is True:
            self.prepare_add_to_group()

        if self.filter_operations(Operation.GRANT) is True:
            self.prepare_grant_group_privileges()
            self.prepare_grant_user_privileges()

        if self.filter_operations(Operation.REVOKE) is True:
            self.prepare_revoke_group_privileges()
            self.prepare_revoke_user_privileges()

        if self.filter_operations(Operation.DROP_FROM_GROUP) is True:
            self.prepare_drop_from_group()

        if self.filter_operations(Operation.DROP) is True:
            self.prepare_drop_subjects()

        return DatabaseAdministrator(self._management_ops)

    def prepare_create_subjects(self):
        self.prepare_subjects(
            self.desired_groups, self.current.groups, Operation.CREATE
        )
        self.prepare_subjects(self.desired_users, self.current.users, Operation.CREATE)

    def prepare_drop_subjects(self):
        self.prepare_subjects(self.desired.groups, self.current_groups, Operation.DROP)
        self.prepare_subjects(self.desired.users, self.current_users, Operation.DROP)

    def prepare_subjects(
        self,
        desired_subjects: Union[list[User], list[Group]],
        current_subjects: Union[list[User], list[Group]],
        operation: Operation,
    ):
        desired_names = set(d.name for d in desired_subjects)
        current_names = set(d.name for d in current_subjects)

        if operation is Operation.CREATE:
            subjects = [
                subject
                for subject in desired_subjects
                if subject.name in desired_names - current_names
            ]

        elif operation is Operation.DROP:
            subjects = [
                subject
                for subject in current_subjects
                if subject.name in current_names - desired_names
            ]

        else:
            raise TypeError(f"Operation can only be CREATE or DROP not {operation}")

        for subject in subjects:
            if isinstance(subject, User):
                self._management_ops.append(
                    UserManagementOperation(subject=subject, operation=operation)
                )
            else:
                self._management_ops.append(
                    GroupManagementOperation(subject=subject, operation=operation)
                )

    def prepare_add_to_group(self):
        group_map = {
            group.name: group for group in self.current.groups + self.desired.groups
        }
        for user in self.desired_users:
            if user.member_of is None or len(user.member_of) == 0:
                continue

            for group_name in user.member_of:
                group = group_map[group_name]

                self._management_ops.append(
                    UserManagementOperation(
                        subject=user, operation=Operation.ADD_TO_GROUP, group=group
                    )
                )

    def prepare_drop_from_group(self):
        group_map = {
            group.name: group for group in self.current.groups + self.desired.groups
        }
        for user in self.current_users:
            if user.member_of is None or len(user.member_of) == 0:
                continue

            for group_name in user.member_of:
                group = group_map[group_name]

                self._management_ops.append(
                    UserManagementOperation(
                        subject=user, operation=Operation.DROP_FROM_GROUP, group=group
                    )
                )

    def prepare_grant_group_privileges(self):
        for group in self.desired_groups:
            if group.privileges is None:
                continue

            privileges = filter(self.filter_privileges, group.privileges)

            try:
                idx = self.current.groups.index(group)
            except ValueError:
                # Group not found, but should be created
                # before privileges are granted. So we assume
                # everything needs to be granted.
                current_privileges = []
            else:
                current_privileges = self.current.groups[idx].privileges

            self.prepare_subject_privileges(
                group, privileges, current_privileges, Operation.GRANT
            )

    def prepare_grant_user_privileges(self):
        for user in self.desired_users:
            if user.privileges is None:
                continue

            privileges = filter(self.filter_privileges, user.privileges)

            try:
                idx = self.current.users.index(user)
            except ValueError:
                # Group not found, but should be created
                # before privileges are granted. So we assume
                # everything needs to be granted.
                current_privileges = []
            else:
                current_privileges = self.current.users[idx].privileges

            self.prepare_subject_privileges(
                user, privileges, current_privileges, Operation.GRANT
            )

    def prepare_revoke_group_privileges(self):
        for group in self.current_groups:
            if group.privileges is None:
                continue

            privileges = filter(self.filter_privileges, group.privileges)

            try:
                idx = self.desired.groups.index(group)
            except ValueError:
                # Group not found, which means it will be deleted
                # assuming no filters. To ensure deletion can happen
                # we need to revoke all privileges.
                desired_privileges = []
            else:
                desired_privileges = self.desired.groups[idx].privileges

            self.prepare_subject_privileges(
                group, desired_privileges, privileges, Operation.GRANT
            )

    def prepare_revoke_user_privileges(self):
        for user in self.current_users:
            if user.privileges is None:
                continue

            privileges = filter(self.filter_privileges, user.privileges)

            try:
                idx = self.desired.users.index(user)
            except ValueError:
                # User not found, which means it will be deleted
                # assuming no filters. To ensure deletion can happen
                # we need to revoke all privileges.
                desired_privileges = []
            else:
                desired_privileges = self.desired.users[idx].privileges

            self.prepare_subject_privileges(
                user, desired_privileges, privileges, Operation.REVOKE
            )

    def prepare_subject_privileges(
        self,
        subject: Union[User, Group],
        desired_privileges: list[Privilege],
        current_privileges: list[Privilege],
        operation: Operation,
    ):
        if operation not in (Operation.GRANT, Operation.REVOKE):
            raise TypeError(
                f"Privileges can only be granted or revoked not {operation}"
            )

        if isinstance(subject, User):
            action_cls = UserManagementOperation
        else:
            action_cls = GroupManagementOperation

        for privilege in desired_privileges:
            if privilege in current_privileges:
                continue

            self._management_ops.append(
                action_cls(subject=subject, operation=operation, privilege=privilege)
            )


class OnError(Enum):
    """Behavior when encountering an error while running Admin actions."""

    CONTINUE = auto()
    ABORT = auto()


class DatabaseAdministrator:
    """An administrator in charge of managing users and groups.

    Attributes:
        ops (list[ManagemenOperation): The operations this DBA will
            execute when calling the manage method.
    """

    def __init__(self, ops: list[ManagementOperation]):
        self.ops = ops

    def queries(self) -> Iterator[tuple[str, ManagementOperation]]:
        """A generator over queries and their actions."""
        for ops in self.ops:
            yield op.query, op

    def manage(
        self,
        connector: RedshiftConnector,
        before_callback: Optional[Callable[[str, ManagementOperation], Any]] = None,
        progress_callback: Optional[Callable[[str, ManagementOperation], Any]] = None,
        success_callback: Optional[Callable[[str, ManagementOperation], Any]] = None,
        on_error_callback: Optional[
            Callable[[str, ManagementOperation, psycopg2.Error], Any]
        ] = None,
        on_error: OnError = OnError.CONTINUE,
    ) -> tuple[bool, Optional[list[ManagementOperationError]]]:
        """Run the given actions and execute callbacks.

        Args:
            connector (RedshiftConnector): A database connector. Currently
                only RedshiftConnector is supported.
            before_callback (Callable, optional): A function called before
                executing an action. It will receive two positional arguments:
                the query and the action that originated it.
            progress_callback (Callable, optional): A function called after
                an action has ran regardless of success status. It will receive
                two positional arguments: the query and the action that
                originated it.
            success_callback (Callable, optional): A function called after
                an action has ran if the execution succeeded. It will receive
                two positional arguments: the query and the action that
                originated it.
            on_error_callback (Callable, optional): A function called after
                an action has ran if the execution failed. It will receive
                three positional arguments: the query, the action that
                originated it and the exception raised.
            on_error (OnError, optional): Control behavior if an action fails:
                OnError.ABORT to immediatly finish, OnError.Continue to
                continue with remaining actions.
        """
        errors = []
        success = True

        for query, action in self.queries():
            if before_callback is not None:
                before_callback(query, action)
            try:
                with connector.connect() as conn:
                    _ = conn.run_query(query)
            except psycopg2.Error as e:
                success = False

                if on_error_callback is not None:
                    on_error_callback(query, action, e)

                if on_error is OnError.ABORT:
                    raise ManagementOperationError(action) from e
                else:
                    exc = ManagementOperationError(action)
                    exc.__cause__ = e
                    errors.append(exc)

            else:
                if success_callback is not None:
                    success_callback(query, action)

            finally:
                if progress_callback is not None:
                    progress_callback(query, action)

        return success, errors
