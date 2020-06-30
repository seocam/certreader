
import sys

import yaml

from .parse import Certificate


def get_certificate():
    return Certificate(sys.argv[1])


def to_yaml():
    certificate = get_certificate()
    print(yaml.dump(certificate._decoded_cert))
