
import yaml

class OID:
    def __init__(self):
        with open("data/oid.yml") as lib_f:
                self.oid_map = yaml.load(lib_f.read(), Loader=yaml.FullLoader)

    def get_nameform(self, oid):
        return self.oid_map.get(oid)

# Use a singleton to read oid yaml just once
_oid = OID()

def get_nameform(oid):
    return _oid.get_nameform(oid)
