from redtape.specification import Specification


def test_read_from_yaml(spec_file):
    with open(spec_file) as yml_file:
        yml_str = yml_file.read()
    spec = Specification.from_yaml(yml_str)
    assert len(spec.users) == 1
