"""The specification module defines the Redtape models.

Redtape models support serialization and deserialization to YAML and JSON.
Moreoever, models can be read created from any DatabaseConnector.
"""
import json
from enum import Enum
from functools import singledispatch, wraps
from itertools import groupby
from typing import Any, Callable, TypeVar

import cattrs
import yaml
from attrs import asdict

from .models import (
    Action,
    DatabaseObject,
    DatabaseObjectType,
    Group,
    Operation,
    Ownerships,
    Password,
    PasswordType,
    Privilege,
    Privileges,
    Specification,
    User,
    ValidationFailure,
)


def value_serializer(inst, attr, value):
    """attrs.asdict value serializer.

    Inverts argument positions before calling serializer since singledispatch
    looks at first argument type, and attrs.asdict calls value_serializer
    with value in the third position.

    Arguments:
        value:
        attr:
        inst:
    """

    return serializer(value, attr, inst)


@singledispatch
def serializer(value, attr, inst):
    """Dispatch to serialization functions.

    The arguments come from attrs.asdict.

    Arguments:
        value:
        attr:
        inst:
    """
    return value


@serializer.register
def _(value: Privileges, attr, inst) -> dict[str, Any]:
    """Serialize privileges by nesting them."""
    nested_privileges: dict[str, Any] = {}

    def action_groupby_key(p: Privilege):
        return p.action.name.lower()

    def object_type_groupby_key(p: Privilege):
        return p.database_object._type.name.lower()

    for object_key, object_group in groupby(value, object_type_groupby_key):
        privileges = nested_privileges.setdefault(object_key, {})
        for action_key, action_group in groupby(object_group, action_groupby_key):
            privileges[action_key] = [p.database_object.name for p in action_group]

    return nested_privileges


@serializer.register
def _(value: Ownerships, attr, inst) -> dict[str, Any]:
    """Serialize Ownerships by nesting them."""

    nested_ownerships: dict[str, Any] = {}

    def object_type_groupby_key(db_obj: DatabaseObject):
        return db_obj._type.name.lower()

    for object_key, object_group in groupby(value, object_type_groupby_key):
        nested_ownerships[object_key] = [obj.name.lower() for obj in object_group]

    return nested_ownerships


@serializer.register
def _(value: Password, attr, inst) -> dict[str, str]:
    """Serialize Password by renaming attributes."""

    d = {
        "type": value._type.value,
    }
    if value.value is not None:
        d["value"] = value.value
    if value.salt is not None:
        d["salt"] = value.salt
    return d


@serializer.register
def _(value: Enum, attr, inst) -> str:
    """Serialize Enums by returning their names in lowercase."""
    return value.name.lower()


T = TypeVar("T")


def add_method(cls_list: list[T], mod=None):
    """Decorate a function to attach it to many classes."""

    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        for cls in cls_list:
            if mod is None:
                setattr(cls, func.__name__, wrapper)
            else:
                setattr(cls, func.__name__, mod(wrapper))

        return func

    return decorator


def filter_none(_, value) -> bool:
    """Filter that checks for None."""
    return value is not None


@add_method([Specification, User, Group])
def to_dict(self: T) -> dict[str, Any]:
    """Serialize self to dictionary using attrs.asdict"""
    return asdict(self, filter=filter_none, value_serializer=value_serializer)


@add_method([Specification, User, Group])
def to_yaml(self: T) -> str:
    """Dump to YAML string after serializing to dictionary."""
    return yaml.safe_dump(self.to_dict())


@add_method([Specification, User, Group])
def to_json(self: T) -> str:
    """Dump to JSON string after serializing to dictionary."""
    return json.dumps(self.to_dict())


_converter = cattrs.GenConverter(prefer_attrib_converters=True)

_converter.register_structure_hook(
    DatabaseObject,
    cattrs.gen.make_dict_unstructure_fn(
        DatabaseObject,
        _converter,
        _type=cattrs.gen.override(rename="type"),
    ),
)


def _deserialize_privileges(d: dict[str, Any], *args, **kwargs) -> Privileges:
    flat_privileges = Privileges()

    for db_obj_type, v in d.items():
        for action, db_objs in v.items():
            action = Action[action.upper()]
            for db_obj in db_objs:
                database_object = DatabaseObject(
                    type=DatabaseObjectType(db_obj_type.upper()),
                    name=db_obj,
                )
                flat_privileges.add(
                    Privilege(database_object=database_object, action=action)
                )

    return flat_privileges


_converter.register_structure_hook(Privileges, _deserialize_privileges)


def _deserialize_ownerships(d: dict[str, Any], *args, **kwargs) -> Ownerships:
    flat_ownerships = Ownerships()

    for db_obj_type, db_objs in d.items():
        for db_obj in db_objs:
            database_object = DatabaseObject(
                type=DatabaseObjectType(db_obj_type.upper()),
                name=db_obj,
            )
            flat_ownerships.add(database_object)

    return flat_ownerships


_converter.register_structure_hook(Ownerships, _deserialize_ownerships)

_converter.register_structure_hook(
    Password,
    cattrs.gen.make_dict_structure_fn(
        Password,
        _converter,
        _type=cattrs.gen.override(rename="type"),
    ),
)
_converter.register_unstructure_hook(
    Group,
    cattrs.gen.make_dict_unstructure_fn(
        Group,
        _converter,
        _cattrs_omit_if_default=True,
    ),
)
_converter.register_unstructure_hook(
    User,
    cattrs.gen.make_dict_unstructure_fn(
        User,
        _converter,
        _cattrs_omit_if_default=True,
    ),
)


@add_method([Specification, User, Group], mod=classmethod)
def from_dict(cls: T, d: dict[str, Any]) -> T:
    """Initialize a class from a Dictionary."""
    return _converter.structure(d, cls)


@add_method([Specification, User, Group], mod=classmethod)
def from_yaml(cls: T, s: str) -> T:
    """Initialize a class by loading a YAML string."""
    return cls.from_dict(yaml.safe_load(s))


@add_method([Specification, User, Group], mod=classmethod)
def from_json(cls: T, s: str):
    """Initialize a class by loading a JSON string."""
    return cls.from_dict(json.loads(s))
