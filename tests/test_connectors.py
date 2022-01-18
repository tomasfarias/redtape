from redtape.connectors import parse_acl


def test_parse_acl():
    """Test the parse_acl function with a few sample ACLs."""
    acl_1 = "{user1=arwdRxtD/user1,group group1=arw/user1,group group2=U*/user1}"

    result_1 = [acl for acl in parse_acl(acl_1, sep=",")]
    expected_1 = [
        ("user1", "user", "a"),
        ("user1", "user", "r"),
        ("user1", "user", "w"),
        ("user1", "user", "d"),
        ("user1", "user", "R"),
        ("user1", "user", "x"),
        ("user1", "user", "t"),
        ("user1", "user", "D"),
        ("group1", "group", "a"),
        ("group1", "group", "r"),
        ("group1", "group", "w"),
        ("group2", "group", "U*"),
    ]
    assert result_1 == expected_1

    acl_2 = "{user2=a*r*w*d*/user2,group group2=U*D*/user2}"

    result_2 = [acl for acl in parse_acl(acl_2, sep=",")]
    expected_2 = [
        ("user2", "user", "a*"),
        ("user2", "user", "r*"),
        ("user2", "user", "w*"),
        ("user2", "user", "d*"),
        ("group2", "group", "U*"),
        ("group2", "group", "D*"),
    ]
    assert result_2 == expected_2

    acl_3 = "=T/user3,user3=CT/user3,user4=C/user3"

    result_3 = [acl for acl in parse_acl(acl_3, sep=",")]
    expected_3 = [
        ("PUBLIC", "PUBLIC", "T"),
        ("user3", "user", "C"),
        ("user3", "user", "T"),
        ("user4", "user", "C"),
    ]
    assert result_3 == expected_3
