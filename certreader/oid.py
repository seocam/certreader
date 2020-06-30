
import yaml

import pkg_resources


class OID:
    def __init__(self):
        oid_yaml = pkg_resources.resource_string(__name__, "data/oid.yml")
        self.oid_map = yaml.load(oid_yaml, Loader=yaml.FullLoader)

    def get_nameform(self, oid):
        return self.oid_map.get(oid)


# Use a singleton to read oid yaml just once
_oid = OID()


def get_nameform(oid):
    return _oid.get_nameform(oid)
