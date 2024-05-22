from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import Name, NameOID, CertificateBuilder, NameAttribute
from cryptography import x509
import datetime

# Información del usuario
country = "US"
state = "California"
locality = "San Francisco"
organization = "My Company"
common_name = "mycompany.com"
email_address = "admin@mycompany.com"

# Generar clave privada
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Crear un certificado auto-firmado con atributos PKCS#9
subject = issuer = Name([
    NameAttribute(NameOID.COUNTRY_NAME, country),
    NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
    NameAttribute(NameOID.LOCALITY_NAME, locality),
    NameAttribute(NameOID.ORGANIZATION_NAME, organization),
    NameAttribute(NameOID.COMMON_NAME, common_name),
    NameAttribute(NameOID.EMAIL_ADDRESS, email_address),
])
now = datetime.datetime.now(datetime.timezone.utc)

certificate = CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    now
).not_valid_after(
    now + datetime.timedelta(days=365)
).add_extension(
    x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
).sign(private_key, hashes.SHA256())

# Serializar y guardar el certificado en un archivo
with open("certificate_with_pkcs9.pem", "wb") as cert_file:
    cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

print("Certificado con atributo PKCS#9 creado y guardado en certificate_with_pkcs9.pem")
