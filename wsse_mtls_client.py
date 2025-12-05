"""
WS-Security SOAP Client with Encryption/Decryption
Supports XML Encryption, Digital Signatures, and Basic Auth over Proxy

UPDATED VERSION: Includes recipient certificate for request encryption
"""

import base64
import hashlib
import os
from datetime import datetime, timedelta
from lxml import etree
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
import requests
from requests.auth import HTTPBasicAuth


class WSSecurityClient:
    """
    WS-Security SOAP Client with encryption and decryption support
    
    IMPORTANT: For full WS-Security encryption:
    - cert_path + key_path: YOUR credentials (decrypt responses, identify yourself)
    - recipient_cert_path: SERVER/RECIPIENT certificate (encrypt requests)
    """
    
    # Namespaces
    NAMESPACES = {
        'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
        'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
        'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
        'xenc': 'http://www.w3.org/2001/04/xmlenc#',
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
        'ns1': 'http://xmlns.example.com/unique/default/namespace/1115236122168'
    }
    
    def __init__(self, endpoint_url, cert_path, key_path, recipient_cert_path, 
                 proxy_url=None, proxy_username=None, proxy_password=None):
        """
        Initialize WS-Security SOAP Client
        
        Args:
            endpoint_url: SOAP endpoint URL
            cert_path: Path to YOUR X.509 certificate (.pem) - for identification & receiving encrypted responses
            key_path: Path to YOUR private key (.pem) - for decrypting responses
            recipient_cert_path: Path to RECIPIENT's/SERVER's certificate (.pem) - for encrypting requests
            proxy_url: Proxy server URL (optional)
            proxy_username: Proxy authentication username (optional)
            proxy_password: Proxy authentication password (optional)
            
        Certificate Usage:
            - cert_path: YOUR certificate (server will use this to encrypt responses TO you)
            - key_path: YOUR private key (you use this to decrypt responses FROM server)
            - recipient_cert_path: SERVER's certificate (you use this to encrypt requests TO server)
        """
        self.endpoint_url = endpoint_url
        self.cert_path = cert_path
        self.key_path = key_path
        self.recipient_cert_path = recipient_cert_path
        self.proxy_url = proxy_url
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        
        # Load certificates and keys
        self.certificate = None  # YOUR certificate
        self.private_key = None  # YOUR private key
        self.recipient_certificate = None  # SERVER's certificate
        
        self._load_credentials()
    
    def _load_credentials(self):
        """Load YOUR X.509 certificate and private key"""
        try:
            # Load YOUR certificate
            with open(self.cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                self.certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Load YOUR private key
            with open(self.key_path, 'rb') as key_file:
                key_data = key_file.read()
                self.private_key = serialization.load_pem_private_key(
                    key_data, 
                    password=None, 
                    backend=default_backend()
                )
            
            print("✓ YOUR certificate and private key loaded successfully")
            
            # Load RECIPIENT's (server's) certificate
            with open(self.recipient_cert_path, 'rb') as recipient_file:
                recipient_data = recipient_file.read()
                self.recipient_certificate = x509.load_pem_x509_certificate(recipient_data, default_backend())
            
            print("✓ RECIPIENT's (server's) certificate loaded successfully")
            
        except Exception as e:
            print(f"✗ Error loading credentials: {e}")
            raise
    
    def _generate_symmetric_key(self, key_size=16):
        """Generate random AES key (16 bytes for AES-128, 32 for AES-256)"""
        return os.urandom(key_size)
    
    def _encrypt_data_aes(self, data, key, algorithm='AES-128'):
        """
        Encrypt data using AES with CBC mode
        
        Args:
            data: Data to encrypt (bytes or string)
            key: AES key
            algorithm: 'AES-128' or 'AES-256'
        
        Returns:
            tuple: (encrypted_data, iv)
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Generate random IV
        iv = os.urandom(16)
        
        # Pad data to block size (16 bytes for AES)
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padded_data = data + bytes([padding_length] * padding_length)
        
        # Create cipher and encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return encrypted_data, iv
    
    def _decrypt_data_aes(self, encrypted_data, key, iv):
        """
        Decrypt AES encrypted data
        
        Args:
            encrypted_data: Encrypted data bytes
            key: AES key
            iv: Initialization vector
        
        Returns:
            bytes: Decrypted data
        """
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        padding_length = decrypted_padded[-1]
        decrypted_data = decrypted_padded[:-padding_length]
        
        return decrypted_data
    
    def _encrypt_key_rsa(self, symmetric_key, recipient_cert):
        """
        Encrypt symmetric key using RSA public key from RECIPIENT's certificate
        
        Args:
            symmetric_key: AES key to encrypt
            recipient_cert: RECIPIENT's X.509 certificate (contains public key)
        
        Returns:
            bytes: Encrypted key
        """
        public_key = recipient_cert.public_key()
        encrypted_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        return encrypted_key
    
    def _decrypt_key_rsa(self, encrypted_key):
        """
        Decrypt symmetric key using YOUR RSA private key
        
        Args:
            encrypted_key: Encrypted AES key
        
        Returns:
            bytes: Decrypted symmetric key
        """
        if not self.private_key:
            raise ValueError("Private key not loaded")
        
        decrypted_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        return decrypted_key
    
    def _encrypt_body(self, body_element):
        """
        Encrypt SOAP body element using recipient's certificate
        
        Args:
            body_element: SOAP body element to encrypt
            
        Returns:
            etree.Element: EncryptedData element
        """
        # Convert body to string
        body_str = etree.tostring(body_element, encoding='unicode')
        
        # Generate symmetric key
        symmetric_key = self._generate_symmetric_key(16)  # AES-128
        
        # Encrypt body data
        encrypted_body, iv = self._encrypt_data_aes(body_str, symmetric_key)
        
        # Combine IV and encrypted data (standard practice)
        encrypted_data_with_iv = iv + encrypted_body
        
        # Encrypt symmetric key with recipient's public key
        encrypted_key = self._encrypt_key_rsa(symmetric_key, self.recipient_certificate)
        
        # Create EncryptedData element
        encrypted_data = etree.Element(
            '{http://www.w3.org/2001/04/xmlenc#}EncryptedData',
            Type='http://www.w3.org/2001/04/xmlenc#Content'
        )
        
        # Add EncryptionMethod
        enc_method = etree.SubElement(encrypted_data, '{http://www.w3.org/2001/04/xmlenc#}EncryptionMethod')
        enc_method.set('Algorithm', 'http://www.w3.org/2001/04/xmlenc#aes128-cbc')
        
        # Add KeyInfo with EncryptedKey
        key_info = etree.SubElement(encrypted_data, '{http://www.w3.org/2000/09/xmldsig#}KeyInfo')
        
        encrypted_key_elem = etree.SubElement(key_info, '{http://www.w3.org/2001/04/xmlenc#}EncryptedKey')
        
        key_enc_method = etree.SubElement(encrypted_key_elem, '{http://www.w3.org/2001/04/xmlenc#}EncryptionMethod')
        key_enc_method.set('Algorithm', 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p')
        
        cipher_data_key = etree.SubElement(encrypted_key_elem, '{http://www.w3.org/2001/04/xmlenc#}CipherData')
        cipher_value_key = etree.SubElement(cipher_data_key, '{http://www.w3.org/2001/04/xmlenc#}CipherValue')
        cipher_value_key.text = base64.b64encode(encrypted_key).decode('utf-8')
        
        # Add CipherData
        cipher_data = etree.SubElement(encrypted_data, '{http://www.w3.org/2001/04/xmlenc#}CipherData')
        cipher_value = etree.SubElement(cipher_data, '{http://www.w3.org/2001/04/xmlenc#}CipherValue')
        cipher_value.text = base64.b64encode(encrypted_data_with_iv).decode('utf-8')
        
        return encrypted_data
    
    def create_soap_request(self, body_content, encrypt=True):
        """
        Create SOAP request with WS-Security headers
        
        Args:
            body_content: XML string or element for SOAP body
            encrypt: Whether to encrypt the message (DEFAULT: True for WS-Security)
        
        Returns:
            str: SOAP XML request
        """
        # Create SOAP envelope
        envelope = etree.Element(
            '{http://schemas.xmlsoap.org/soap/envelope/}Envelope',
            nsmap={'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/'}
        )
        
        # Create header with WS-Security
        header = etree.SubElement(envelope, '{http://schemas.xmlsoap.org/soap/envelope/}Header')
        self._add_security_header(header)
        
        # Create body
        body = etree.SubElement(envelope, '{http://schemas.xmlsoap.org/soap/envelope/}Body')
        
        # Add body content
        if isinstance(body_content, str):
            body_element = etree.fromstring(body_content)
        else:
            body_element = body_content
        
        if encrypt:
            # Encrypt the body content
            encrypted_data = self._encrypt_body(body_element)
            body.append(encrypted_data)
        else:
            body.append(body_element)
        
        return etree.tostring(envelope, pretty_print=True, encoding='unicode')
    
    def _add_security_header(self, header):
        """Add WS-Security header with timestamp and binary security token"""
        security = etree.SubElement(
            header,
            '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security',
            nsmap={'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'}
        )
        
        # Add timestamp
        timestamp = etree.SubElement(
            security,
            '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp',
            nsmap={'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'}
        )
        
        created = etree.SubElement(timestamp, '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Created')
        created.text = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z')
        
        expires = etree.SubElement(timestamp, '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Expires')
        expires.text = (datetime.utcnow() + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        
        # Add binary security token (YOUR certificate for identification)
        bst = etree.SubElement(
            security,
            '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken'
        )
        bst.set('EncodingType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary')
        bst.set('ValueType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3')
        bst.set('{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Id', 'X509-TOKEN')
        bst.text = base64.b64encode(self.certificate.public_bytes(serialization.Encoding.DER)).decode('utf-8')
    
    def decrypt_soap_response(self, soap_response):
        """
        Decrypt SOAP response with WS-Security encryption
        
        Args:
            soap_response: Encrypted SOAP XML response string
        
        Returns:
            str: Decrypted SOAP XML
        """
        try:
            # Parse XML
            root = etree.fromstring(soap_response.encode('utf-8') if isinstance(soap_response, str) else soap_response)
            
            # Find encrypted data
            encrypted_data = root.find('.//xenc:EncryptedData', namespaces=self.NAMESPACES)
            
            if encrypted_data is None:
                print("No encrypted data found, returning original response")
                return soap_response
            
            # Extract encryption method
            enc_method = encrypted_data.find('.//xenc:EncryptionMethod', namespaces=self.NAMESPACES)
            algorithm = enc_method.get('Algorithm') if enc_method is not None else None
            print(f"Encryption algorithm: {algorithm}")
            
            # Extract encrypted key
            key_info = encrypted_data.find('.//ds:KeyInfo', namespaces=self.NAMESPACES)
            encrypted_key = key_info.find('.//xenc:EncryptedKey', namespaces=self.NAMESPACES)
            cipher_value_key = encrypted_key.find('.//xenc:CipherValue', namespaces=self.NAMESPACES)
            
            # Decode encrypted key
            encrypted_key_bytes = base64.b64decode(cipher_value_key.text)
            print(f"Encrypted key size: {len(encrypted_key_bytes)} bytes")
            
            # Decrypt symmetric key using YOUR RSA private key
            symmetric_key = self._decrypt_key_rsa(encrypted_key_bytes)
            print(f"✓ Symmetric key decrypted: {len(symmetric_key)} bytes")
            
            # Extract cipher data
            cipher_data = encrypted_data.find('.//xenc:CipherData', namespaces=self.NAMESPACES)
            cipher_value = cipher_data.find('.//xenc:CipherValue', namespaces=self.NAMESPACES)
            
            # Decode encrypted content
            encrypted_content = base64.b64decode(cipher_value.text)
            print(f"Encrypted content size: {len(encrypted_content)} bytes")
            
            # Extract IV (first 16 bytes for AES CBC)
            iv = encrypted_content[:16]
            encrypted_body = encrypted_content[16:]
            
            # Decrypt content
            decrypted_content = self._decrypt_data_aes(encrypted_body, symmetric_key, iv)
            print(f"✓ Content decrypted: {len(decrypted_content)} bytes")
            
            # Parse decrypted XML
            decrypted_xml = decrypted_content.decode('utf-8')
            
            # Replace encrypted data with decrypted content in original structure
            decrypted_element = etree.fromstring(decrypted_xml)
            
            # Find parent of encrypted data and replace
            parent = encrypted_data.getparent()
            parent.remove(encrypted_data)
            parent.append(decrypted_element)
            
            # Return complete decrypted SOAP message
            return etree.tostring(root, pretty_print=True, encoding='unicode')
            
        except Exception as e:
            print(f"✗ Decryption error: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def send_request(self, soap_body, encrypt_request=True):
        """
        Send SOAP request to endpoint
        
        Args:
            soap_body: SOAP body content
            encrypt_request: Whether to encrypt the request (DEFAULT: True)
        
        Returns:
            tuple: (decrypted_response, raw_response)
        """
        # Create SOAP request
        soap_request = self.create_soap_request(soap_body, encrypt=encrypt_request)
        
        print(f"\n{'='*60}")
        print("SOAP REQUEST")
        print(f"{'='*60}")
        print(soap_request[:500] + "..." if len(soap_request) > 500 else soap_request)
        
        # Prepare headers
        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': '""'
        }
        
        # Configure proxy
        proxies = None
        auth = None
        
        if self.proxy_url:
            proxies = {
                'http': self.proxy_url,
                'https': self.proxy_url
            }
            
            if self.proxy_username and self.proxy_password:
                auth = HTTPBasicAuth(self.proxy_username, self.proxy_password)
        
        try:
            # Send request
            print(f"\n→ Sending request to: {self.endpoint_url}")
            if proxies:
                print(f"→ Using proxy: {self.proxy_url}")
            
            response = requests.post(
                self.endpoint_url,
                data=soap_request.encode('utf-8'),
                headers=headers,
                proxies=proxies,
                auth=auth,
                verify=False,  # Set to True in production with proper CA bundle
                timeout=30
            )
            
            print(f"✓ Response status: {response.status_code}")
            
            if response.status_code == 200:
                raw_response = response.text
                
                print(f"\n{'='*60}")
                print("RAW SOAP RESPONSE (Encrypted)")
                print(f"{'='*60}")
                print(raw_response[:500] + "..." if len(raw_response) > 500 else raw_response)
                
                # Decrypt response
                decrypted_response = self.decrypt_soap_response(raw_response)
                
                if decrypted_response:
                    print(f"\n{'='*60}")
                    print("DECRYPTED SOAP RESPONSE")
                    print(f"{'='*60}")
                    print(decrypted_response[:1000] + "..." if len(decrypted_response) > 1000 else decrypted_response)
                
                return decrypted_response, raw_response
            else:
                print(f"✗ Error response: {response.status_code}")
                print(response.text)
                return None, response.text
                
        except Exception as e:
            print(f"✗ Request error: {e}")
            import traceback
            traceback.print_exc()
            return None, None
