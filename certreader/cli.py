
import json
import sys

from datetime import datetime

import yaml

from .parse import Certificate


def get_certificate():
    return Certificate(sys.argv[1])


def to_yaml():
    certificate = get_certificate()
    print(yaml.dump(certificate._decoded_cert))


def json_serializer(obj):
    if isinstance(obj, datetime):
        return str(obj)

def to_json():
    certificate = get_certificate()
    json_cert = json.dumps(
        certificate._decoded_cert,
        default=json_serializer,
        indent=2,
    )
    print(json_cert)
