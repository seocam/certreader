from cryptography import x509
from cryptography.hazmat.backends import default_backend

from pyasn1.codec.der import decoder
from pyasn1.type import char, namedtype, tag, univ

from .oid import get_nameform


def hexlify(binary):
    return ":".join([bytes([byte]).hex() for byte in binary]).upper()


class _PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "name-type",
            univ.Integer().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            ),
        ),
        namedtype.NamedType(
            "name-string",
            univ.SequenceOf(char.GeneralString()).subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            ),
        ),
    )


class _KRB5PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "realm",
            char.GeneralString().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            ),
        ),
        namedtype.NamedType(
            "principalName",
            _PrincipalName().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            ),
        ),
    )


class UniversalPrincipalName(x509.OtherName):
    "Universal Principal Name x509 OtherName implementation."

    # pylint: disable=too-few-public-methods

    oid = "1.3.6.1.4.1.311.20.2.3"

    def __init__(self, type_id, value):
        super(UniversalPrincipalName, self).__init__(type_id, value)
        self.decoded_value = self._decode_name(value)
        self.node_name = "Universal Principal Name (UPN)"

    @staticmethod
    def _decode_name(data):
        return decoder.decode(data, asn1Spec=char.UTF8String())[0]


class KRB5PrincipalName(x509.OtherName):
    """Kerberos Principal x509 OtherName implementation."""

    # pylint: disable=too-few-public-methods

    oid = "1.3.6.1.5.2.2"

    def __init__(self, type_id, value):
        super(KRB5PrincipalName, self).__init__(type_id, value)
        self.decoded_value = self._decode_name(value)
        self.node_name = "Kerberos principalname"

    @staticmethod
    def _decode_name(data):
        # pylint: disable=unsubscriptable-object
        principal = decoder.decode(data, asn1Spec=_KRB5PrincipalName())[0]
        realm = str(principal["realm"]).replace("\\", "\\\\").replace("@", "\\@")

        name = principal["principalName"]["name-string"]
        name = u"/".join(
            str(n).replace("\\", "\\\\").replace("/", "\\/").replace("@", "\\@")
            for n in name
        )
        name = u"%s@%s" % (name, realm)
        return name


class Certificate:

    subjectAltName_class_name_map = {
        x509.DNSName: "DNS",
        x509.IPAddress: "IP Address",
        x509.RFC822Name: "email",
    }

    subjectAltName_oid_class_map = {
        x509.ObjectIdentifier("1.3.6.1.5.2.2"): KRB5PrincipalName,
        x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"): UniversalPrincipalName,
    }

    def __init__(self, encoded_certificate):
        self._x509_cert = self.load_certificate(encoded_certificate)
        self._decoded_cert = self._decode_x509_cert()

    @staticmethod
    def load_certificate(encoded_certificate):
        content = None
        if hasattr("read", encoded_certificate):
            content = encoded_certificate.read()
        elif isinstance(encoded_certificate, str):
            with open(encoded_certificate, "r") as cert_file:
                content = cert_file.read()
        else:
            print("Could not load certificate.")

        return x509.load_pem_x509_certificate(content.encode("utf8"), default_backend())

    def _decode_x509_cert(self):
        decoded = {}
        decoded["subject"] = self._get_subject_from_x509()
        decoded["extensions"] = self._get_extensions()
        decoded["signature_algorithm"] = self._get_signature_algorithm()
        decoded["key_size"] = self._x509_cert.public_key().key_size
        decoded["validity"] = self._get_validity()
        return decoded

    def _get_validity(self):
        return {
            "not_valid_after": self._x509_cert.not_valid_after,
            "not_valid_before": self._x509_cert.not_valid_before,
        }

    def _get_signature_algorithm(self):
        algorithm = self._x509_cert.signature_algorithm_oid._name
        signature = hexlify(self._x509_cert.signature)
        return {"algorithm": algorithm, "signature": signature}

    def _get_subject_from_x509(self):
        subject = []
        for name_attr in self._x509_cert.subject:
            name = name_attr.oid._name
            oid = name_attr.oid.dotted_string
            value = name_attr.value
            subject.append({"name": name, "oid": oid, "value": value})
        return subject

    def _get_extensions(self):
        extensions = {}
        for ext in self._x509_cert.extensions:
            name = ext.oid._name
            if hasattr(self, "_get_extension_" + name):
                extension_value = getattr(self, "_get_extension_" + name)(ext)
                extensions[name] = {"value": extension_value, "critical": ext.critical}
            else:
                extensions[name] = "** Not implemented by parser **"
        return extensions

    def _get_extension_cRLDistributionPoints(self, ext):
        values = []
        for dist_point in ext.value:
            value = {
                "full_name": [full_name.value for full_name in dist_point.full_name],
            }

            crl_issuer = []
            for issuer in dist_point.crl_issuer or []:
                crl_issuer.append(
                    {dn_part.oid._name: dn_part.value for dn_part in issuer.value}
                )

            if crl_issuer:
                value["crl_issuer"] = crl_issuer

            values.append(value)

        return values

    def _get_extension_extendedKeyUsage(self, ext):
        values = []
        for eku in ext.value:
            values.append(
                {"name": get_nameform(eku.dotted_string), "oid": eku.dotted_string}
            )
        return values

    def _get_extension_authorityInfoAccess(self, ext):
        values = []
        for info in ext.value:
            values.append(
                {
                    "method": info.access_method._name,
                    "location": info.access_location.value,
                }
            )
        return values

    def _get_extension_basicConstraints(self, ext):
        return {
            constraint.lstrip("_"): value
            for constraint, value in vars(ext.value).items()
            if value is not None
        }

    def _get_extension_authorityKeyIdentifier(self, ext):
        return hexlify(ext.value.key_identifier)

    def _get_extension_subjectKeyIdentifier(self, ext):
        return hexlify(ext.value.digest)

    def _get_extension_keyUsage(self, ext):
        return [ku.lstrip("_") for ku, active in vars(ext.value).items() if active]

    def _get_extension_subjectAltName(self, ext):
        values = []
        for san in ext.value:
            name = self.subjectAltName_class_name_map.get(san.__class__, "Unknown")
            value = san.value
            try:
                oid = san.type_id
            except AttributeError:
                oid = None

            if oid in self.subjectAltName_oid_class_map:
                san_class = self.subjectAltName_oid_class_map.get(oid)
                san_obj = san_class(oid, value)
                name = san_obj.node_name
                value = san_obj.decoded_value

            san_attrs = {
                "name": name,
                "value": str(value),
            }
            if oid:
                san_attrs["oid"] = oid.dotted_string
            values.append(san_attrs)

        return values
