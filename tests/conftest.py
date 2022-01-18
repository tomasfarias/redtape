import pytest
import yaml


@pytest.fixture(scope="session")
def spec_file(tmp_path_factory):
    """Create a test configuration file."""
    p = tmp_path_factory.mktemp("config") / "redtape.yml"
    content = yaml.safe_dump(
        {
            "users": [
                {
                    "name": "test_user_1",
                    "is_superuser": True,
                    "member_of": ["my_user_group_1", "my_user_group_2"],
                    "password": {
                        "type": "md5",
                        "value": "md5thisisnotanmd5hash",
                    },
                    "privileges": {
                        "table": {
                            "select": [
                                "one_table",
                                "another_table",
                                "database_name.*.*",
                            ],
                        },
                        "schema": {
                            "create": [
                                "a_schema",
                                "database_name.*",
                            ]
                        },
                        "database": {
                            "temporary": ["my_db"],
                        },
                    },
                }
            ]
        }
    )
    p.write_text(content)
    return p
