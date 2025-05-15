"""
Let's just get some public key auth in place

What we want client to do:
    - Generate public/private key pairs (either use RSA or ECC etc)
        -- allow (require) the keys to be password protected
    - List our known keys?
        -- We have a place we store keys we generated?
    - Auth with our server to get a JWT etc

Be CLI

Future:
    -- Expand to support smart cards?
        --yubi key
    -- SSH Keys? (I mean is this really any different?)
"""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec


def main():
    """
    To start lets just generate a root CA and intermediate certificate. then we can use that to create leaf (or ID certs)

    Then we can have our server trust any certificates derived from the root certificate
    """

    # Create the root certificate
    root_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "DC"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "DC"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mitchell PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Mitchell PKI Root CA"),
        ]
    )
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        # Valid for one year
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )


if __name__ == "__main__":
    main()
