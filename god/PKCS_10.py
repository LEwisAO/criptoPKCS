from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import Name, NameOID, CertificateSigningRequestBuilder, NameAttribute

# Información del usuario
country = "US"
state = "California"
locality = "San Francisco"
organization = "My Company"
common_name = "mycompany.com"
email_address = "admin@mycompany.com"

# Generar clave privada
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Crear una solicitud de certificado (CSR)
csr = CertificateSigningRequestBuilder().subject_name(Name([
    NameAttribute(NameOID.COUNTRY_NAME, country),
    NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
    NameAttribute(NameOID.LOCALITY_NAME, locality),
    NameAttribute(NameOID.ORGANIZATION_NAME, organization),
    NameAttribute(NameOID.COMMON_NAME, common_name),
    NameAttribute(NameOID.EMAIL_ADDRESS, email_address),
])).sign(private_key, hashes.SHA256())

# Serializar y guardar la solicitud de certificado en un archivo
with open("certificate_request.pem", "wb") as csr_file:
    csr_file.write(csr.public_bytes(serialization.Encoding.PEM))

print("Solicitud de certificado PKCS#10 creada y guardada en certificate_request.pem")
