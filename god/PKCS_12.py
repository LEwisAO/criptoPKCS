from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
import datetime
import getpass

# Generar una clave privada RSA
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Crear un certificado auto-firmado para asociarlo a la clave privada
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyOrg"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"myorg.com"),
])

# Fechas de validez del certificado
one_day = datetime.timedelta(1, 0, 0)
today = datetime.datetime.today()
certificate = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    today - one_day
).not_valid_after(
    today + (one_day * 365)  # Un año de validez
).sign(private_key, hashes.SHA256())

# Pedir al usuario que introduzca una contraseña para cifrar el archivo PKCS#12
password = getpass.getpass("Introduce una contraseña para cifrar el archivo PKCS#12: ").encode()

# Empaquetar la clave privada y el certificado en un archivo PKCS#12
p12 = pkcs12.serialize_key_and_certificates(
    b"my_key_and_cert", private_key, certificate, None,
    serialization.BestAvailableEncryption(password)
)

# Guardar el archivo PKCS#12
with open("my_key_and_certificate.p12", "wb") as f:
    f.write(p12)

print("Archivo PKCS#12 creado con éxito.")

# Pedir al usuario que introduzca la contraseña para descifrar el archivo PKCS#12
password = getpass.getpass("Introduce la contraseña para ver los datos guardados en el archivo PKCS#12: ").encode()

# Cargar y descifrar el contenido del archivo PKCS#12
with open("my_key_and_certificate.p12", "rb") as f:
    p12_data = f.read()

try:
    (private_key_loaded, certificate_loaded, additional_certs) = pkcs12.load_key_and_certificates(
        p12_data, password)
    print("Datos descifrados del archivo PKCS#12:")
    print("Clave privada: <RSAPrivateKey>")
    print("Certificado:", certificate_loaded.public_bytes(serialization.Encoding.PEM).decode())
    print("Detalles del Certificado:")
    print("--País:", certificate_loaded.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value)
    print("--Estado/Provincia:", certificate_loaded.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value)
    print("--Localidad:", certificate_loaded.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value)
    print("--Organización:", certificate_loaded.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value)
    print("--Nombre Común:", certificate_loaded.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
    print("--Algoritmo de Firma:", certificate_loaded.signature_algorithm_oid._name)
    print("--Válido desde:", certificate_loaded.not_valid_before)
    print("--Válido hasta:", certificate_loaded.not_valid_after)
except ValueError as e:
    print("Contraseña incorrecta o archivo PKCS#12 dañado:", e)
