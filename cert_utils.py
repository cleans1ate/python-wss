"""
Certificate utilities for WSSE mTLS client
Includes certificate validation, conversion, and testing tools
"""

import os
import ssl
import socket
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import OpenSSL


class CertificateValidator:
    """Validate and inspect certificates"""
    
    @staticmethod
    def load_certificate(cert_path):
        """Load certificate from file"""
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
            
        try:
            if b'-----BEGIN CERTIFICATE-----' in cert_data:
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            else:
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
            return cert
        except Exception as e:
            raise Exception(f"Failed to load certificate: {e}")
    
    @staticmethod
    def inspect_certificate(cert_path):
        """Inspect certificate and print details"""
        cert = CertificateValidator.load_certificate(cert_path)
        
        print(f"\n{'='*60}")
        print(f"Certificate: {cert_path}")
        print(f"{'='*60}")
        
        # Subject
        print(f"\nSubject:")
        for attr in cert.subject:
            print(f"  {attr.oid._name}: {attr.value}")
        
        # Issuer
        print(f"\nIssuer:")
        for attr in cert.issuer:
            print(f"  {attr.oid._name}: {attr.value}")
        
        # Validity
        print(f"\nValidity:")
        print(f"  Not Before: {cert.not_valid_before_utc}")
        print(f"  Not After:  {cert.not_valid_after_utc}")
        
        # Check if valid
        now = datetime.utcnow()
        if now < cert.not_valid_before_utc:
            print(f"  Status: ⚠️  NOT YET VALID")
        elif now > cert.not_valid_after_utc:
            print(f"  Status: ❌ EXPIRED")
        else:
            days_left = (cert.not_valid_after_utc - now).days
            print(f"  Status: ✅ VALID ({days_left} days remaining)")
        
        # Serial number
        print(f"\nSerial Number: {cert.serial_number}")
        
        # Public key
        pub_key = cert.public_key()
        print(f"\nPublic Key:")
        print(f"  Algorithm: {pub_key.__class__.__name__}")
        if hasattr(pub_key, 'key_size'):
            print(f"  Key Size: {pub_key.key_size} bits")
        
        # Extensions
        print(f"\nExtensions:")
        try:
            for ext in cert.extensions:
                print(f"  - {ext.oid._name}: {ext.critical}")
        except:
            print("  No extensions or unable to parse")
        
        print(f"\n{'='*60}\n")
        
        return cert
    
    @staticmethod
    def validate_certificate_pair(cert_path, key_path):
        """Validate that certificate and key match"""
        print(f"Validating certificate-key pair...")
        
        # Load certificate
        cert = CertificateValidator.load_certificate(cert_path)
        
        # Load private key
        with open(key_path, 'rb') as f:
            key_data = f.read()
        
        try:
            if b'-----BEGIN' in key_data:
                private_key = serialization.load_pem_private_key(
                    key_data, password=None, backend=default_backend()
                )
            else:
                private_key = serialization.load_der_private_key(
                    key_data, password=None, backend=default_backend()
                )
        except Exception as e:
            raise Exception(f"Failed to load private key: {e}")
        
        # Get public key from certificate
        cert_public_key = cert.public_key()
        
        # Get public key from private key
        key_public_key = private_key.public_key()
        
        # Compare public keys
        cert_pub_bytes = cert_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_pub_bytes = key_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        if cert_pub_bytes == key_pub_bytes:
            print("✅ Certificate and key match!")
            return True
        else:
            print("❌ Certificate and key DO NOT match!")
            return False
    
    @staticmethod
    def test_mtls_connection(hostname, port, client_cert, client_key, server_ca=None):
        """Test mTLS connection to server"""
        print(f"\nTesting mTLS connection to {hostname}:{port}...")
        
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        # Load client certificate and key
        context.load_cert_chain(certfile=client_cert, keyfile=client_key)
        
        # Load server CA if provided
        if server_ca:
            context.load_verify_locations(cafile=server_ca)
        
        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    print("✅ mTLS connection successful!")
                    
                    # Get certificate info
                    cert = ssock.getpeercert()
                    print(f"\nServer Certificate:")
                    print(f"  Subject: {dict(x[0] for x in cert['subject'])}")
                    print(f"  Issuer: {dict(x[0] for x in cert['issuer'])}")
                    print(f"  Version: {cert['version']}")
                    print(f"  Serial Number: {cert['serialNumber']}")
                    print(f"  Not Before: {cert['notBefore']}")
                    print(f"  Not After: {cert['notAfter']}")
                    
                    # Cipher info
                    print(f"\nConnection Info:")
                    print(f"  Protocol: {ssock.version()}")
                    print(f"  Cipher: {ssock.cipher()}")
                    
                    return True
        except ssl.SSLError as e:
            print(f"❌ SSL Error: {e}")
            return False
        except socket.timeout:
            print(f"❌ Connection timeout")
            return False
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False


class CertificateConverter:
    """Convert between certificate formats"""
    
    @staticmethod
    def pem_to_der(pem_file, der_file):
        """Convert PEM to DER format"""
        with open(pem_file, 'rb') as f:
            pem_data = f.read()
        
        if b'-----BEGIN CERTIFICATE-----' in pem_data:
            cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        else:
            print("Input is not in PEM format")
            return
        
        der_data = cert.public_bytes(serialization.Encoding.DER)
        
        with open(der_file, 'wb') as f:
            f.write(der_data)
        
        print(f"✅ Converted {pem_file} to {der_file}")
    
    @staticmethod
    def der_to_pem(der_file, pem_file):
        """Convert DER to PEM format"""
        with open(der_file, 'rb') as f:
            der_data = f.read()
        
        cert = x509.load_der_x509_certificate(der_data, default_backend())
        pem_data = cert.public_bytes(serialization.Encoding.PEM)
        
        with open(pem_file, 'wb') as f:
            f.write(pem_data)
        
        print(f"✅ Converted {der_file} to {pem_file}")
    
    @staticmethod
    def extract_public_key(cert_file, output_file):
        """Extract public key from certificate"""
        cert = CertificateValidator.load_certificate(cert_file)
        public_key = cert.public_key()
        
        pem_data = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(output_file, 'wb') as f:
            f.write(pem_data)
        
        print(f"✅ Extracted public key to {output_file}")
    
    @staticmethod
    def pfx_to_pem(pfx_file, password, cert_output, key_output):
        """Convert PFX/P12 to PEM format"""
        with open(pfx_file, 'rb') as f:
            pfx_data = f.read()
        
        # Load PFX
        pfx = OpenSSL.crypto.load_pkcs12(pfx_data, password.encode() if password else None)
        
        # Extract certificate
        cert_pem = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            pfx.get_certificate()
        )
        
        with open(cert_output, 'wb') as f:
            f.write(cert_pem)
        
        # Extract private key
        key_pem = OpenSSL.crypto.dump_privatekey(
            OpenSSL.crypto.FILETYPE_PEM,
            pfx.get_privatekey()
        )
        
        with open(key_output, 'wb') as f:
            f.write(key_pem)
        
        print(f"✅ Converted PFX to:")
        print(f"   Certificate: {cert_output}")
        print(f"   Private Key: {key_output}")


def validate_all_certificates(config):
    """Validate all certificates in configuration"""
    print("\n" + "="*60)
    print("CERTIFICATE VALIDATION REPORT")
    print("="*60)
    
    validator = CertificateValidator()
    
    # Check client certificate
    print("\n1. CLIENT CERTIFICATE (mTLS)")
    try:
        validator.inspect_certificate(config['client_cert'])
        validator.validate_certificate_pair(config['client_cert'], config['client_key'])
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Check encryption certificate
    print("\n2. ENCRYPTION CERTIFICATE")
    try:
        validator.inspect_certificate(config['encryption_cert'])
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Check signing certificate
    print("\n3. SIGNING CERTIFICATE")
    try:
        validator.inspect_certificate(config['signing_cert'])
        validator.validate_certificate_pair(config['signing_cert'], config['signing_key'])
    except Exception as e:
        print(f"❌ Error: {e}")
    
    # Test connection if server details provided
    if 'server_host' in config and 'server_port' in config:
        print("\n4. MTLS CONNECTION TEST")
        validator.test_mtls_connection(
            config['server_host'],
            config['server_port'],
            config['client_cert'],
            config['client_key'],
            config.get('server_ca')
        )


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Certificate Utilities")
        print("\nUsage:")
        print("  python cert_utils.py inspect <cert_file>")
        print("  python cert_utils.py validate <cert_file> <key_file>")
        print("  python cert_utils.py test <hostname> <port> <cert> <key> [ca]")
        print("  python cert_utils.py convert-pem-der <pem_file> <der_file>")
        print("  python cert_utils.py convert-pfx-pem <pfx_file> <password> <cert_out> <key_out>")
        print("  python cert_utils.py validate-all")
        sys.exit(1)
    
    command = sys.argv[1]
    validator = CertificateValidator()
    converter = CertificateConverter()
    
    if command == "inspect" and len(sys.argv) >= 3:
        validator.inspect_certificate(sys.argv[2])
    
    elif command == "validate" and len(sys.argv) >= 4:
        validator.validate_certificate_pair(sys.argv[2], sys.argv[3])
    
    elif command == "test" and len(sys.argv) >= 6:
        hostname = sys.argv[2]
        port = int(sys.argv[3])
        cert = sys.argv[4]
        key = sys.argv[5]
        ca = sys.argv[6] if len(sys.argv) > 6 else None
        validator.test_mtls_connection(hostname, port, cert, key, ca)
    
    elif command == "convert-pem-der" and len(sys.argv) >= 4:
        converter.pem_to_der(sys.argv[2], sys.argv[3])
    
    elif command == "convert-pfx-pem" and len(sys.argv) >= 6:
        converter.pfx_to_pem(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    
    elif command == "validate-all":
        # Example configuration
        config = {
            'client_cert': 'certs/client_cert.pem',
            'client_key': 'certs/client_key.pem',
            'encryption_cert': 'certs/encryption_cert.pem',
            'signing_cert': 'certs/signing_cert.pem',
            'signing_key': 'certs/signing_key.pem',
            'server_ca': 'certs/server_ca.pem',
            'server_host': 'your-server.com',
            'server_port': 443
        }
        validate_all_certificates(config)
    
    else:
        print("Invalid command or insufficient arguments")
        sys.exit(1)
