from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import Name, NameOID, CertificateBuilder, NameAttribute
import datetime

# Generar clave privada
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Serializar y guardar la clave privada en un archivo
with open("private_key.pem", "wb") as key_file:
    key_file.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Crear un certificado auto-firmado
subject = issuer = Name([
    NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    NameAttribute(NameOID.COMMON_NAME, u"mycompany.com"),
])
now = datetime.datetime.now(datetime.timezone.utc)
certificate = CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    private_key.public_key()
).serial_number(
    1000
).not_valid_before(
    now
).not_valid_after(
    now + datetime.timedelta(days=365)
).sign(private_key, hashes.SHA256())

# Serializar y guardar el certificado en un archivo
with open("certificate.pem", "wb") as cert_file:
    cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

print("private_key.pem and certificate.pem have been created.")
