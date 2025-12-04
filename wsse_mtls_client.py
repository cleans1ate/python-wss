"""
SOAP Client with WS-Security (WSSE) and mTLS support
Handles XML encryption, signing, and mutual TLS authentication
FIXED VERSION - Resolves xmlsec template and decryption issues
"""

import requests
from lxml import etree
from zeep import Client, Settings
from zeep.transports import Transport
from zeep.wsse.signature import Signature
from requests import Session
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from datetime import datetime, timedelta
import uuid


class WSSEMTLSClient:
    """SOAP client with WS-Security and mTLS support"""
    
    def __init__(self, 
                 wsdl_url,
                 endpoint_url,
                 client_cert_path,
                 client_key_path,
                 server_cert_path=None,
                 encryption_cert_path=None,
                 signing_cert_path=None,
                 signing_key_path=None,
                 encrypt_request=False,
                 sign_request=False):
        """
        Initialize the WSSE mTLS client
        
        Args:
            wsdl_url: WSDL service URL
            endpoint_url: Actual endpoint URL
            client_cert_path: Path to client certificate for mTLS (.crt or .pem)
            client_key_path: Path to client private key for mTLS (.key or .pem)
            server_cert_path: Path to server CA certificate (optional)
            encryption_cert_path: Path to server's public cert for encrypting requests (.crt)
            signing_cert_path: Path to signing certificate (.crt)
            signing_key_path: Path to signing private key (.key)
            encrypt_request: Whether to encrypt outgoing requests (default: False)
            sign_request: Whether to sign outgoing requests (default: False)
        """
        self.wsdl_url = wsdl_url
        self.endpoint_url = endpoint_url
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self.server_cert_path = server_cert_path
        self.encryption_cert_path = encryption_cert_path
        self.signing_cert_path = signing_cert_path
        self.signing_key_path = signing_key_path
        self.encrypt_request = encrypt_request
        self.sign_request = sign_request
        
        # Setup session with mTLS
        self.session = self._create_mtls_session()
        
    def _create_mtls_session(self):
        """Create requests session with mTLS configuration"""
        session = Session()
        
        # Configure client certificate for mTLS
        session.cert = (self.client_cert_path, self.client_key_path)
        
        # Configure server certificate verification
        if self.server_cert_path:
            session.verify = self.server_cert_path
        else:
            # In production, always verify! This is for testing only
            session.verify = True
            
        return session
    
    def _create_security_header(self, envelope):
        """Create WS-Security header with timestamp and certificate"""
        
        # Namespaces
        SOAPENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
        WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
        
        # Get or create Header
        header = envelope.find(f"{{{SOAPENV_NS}}}Header")
        if header is None:
            body = envelope.find(f"{{{SOAPENV_NS}}}Body")
            header = etree.Element(f"{{{SOAPENV_NS}}}Header")
            envelope.insert(0, header)
        
        # Create Security element
        security = etree.SubElement(header, f"{{{WSSE_NS}}}Security")
        security.set(f"{{{SOAPENV_NS}}}mustUnderstand", "1")
        
        # Add Timestamp
        timestamp = etree.SubElement(security, f"{{{WSU_NS}}}Timestamp")
        timestamp.set(f"{{{WSU_NS}}}Id", f"TS-{uuid.uuid4().hex}")
        
        created = etree.SubElement(timestamp, f"{{{WSU_NS}}}Created")
        created.text = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        
        expires = etree.SubElement(timestamp, f"{{{WSU_NS}}}Expires")
        expires.text = (datetime.utcnow() + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        
        # Add BinarySecurityToken (X.509 certificate)
        if self.signing_cert_path:
            with open(self.signing_cert_path, 'rb') as f:
                cert_data = f.read()
                if b'-----BEGIN CERTIFICATE-----' in cert_data:
                    # PEM format
                    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                else:
                    # DER format
                    cert = x509.load_der_x509_certificate(cert_data, default_backend())
                
                cert_der = cert.public_bytes(serialization.Encoding.DER)
                cert_b64 = base64.b64encode(cert_der).decode('utf-8')
                
                bst = etree.SubElement(security, f"{{{WSSE_NS}}}BinarySecurityToken")
                bst.set("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
                bst.set("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
                bst.set(f"{{{WSU_NS}}}Id", f"X509-{uuid.uuid4().hex}")
                bst.text = cert_b64
        
        return envelope
    
    def _sign_envelope(self, envelope):
        """Sign the SOAP envelope using XML Signature"""
        try:
            import xmlsec
        except ImportError:
            raise ImportError("xmlsec library is required for signing. Install: pip install xmlsec")
        
        if not self.signing_key_path:
            raise ValueError("Signing key path is required for signing requests")
        
        print("Signing SOAP envelope...")
        
        # Namespaces
        SOAPENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
        WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
        DS_NS = "http://www.w3.org/2000/09/xmldsig#"
        
        # Get security header
        header = envelope.find(f".//{{{WSSE_NS}}}Security")
        if header is None:
            raise ValueError("Security header must exist before signing")
        
        # Get Body and add wsu:Id for reference
        body = envelope.find(f"{{{SOAPENV_NS}}}Body")
        body_id = f"id-{uuid.uuid4().hex}"
        body.set(f"{{{WSU_NS}}}Id", body_id)
        
        # Load private key
        with open(self.signing_key_path, 'rb') as key_file:
            key_data = key_file.read()
        
        # Create key
        if b'-----BEGIN' in key_data:
            key = xmlsec.Key.from_memory(key_data, xmlsec.constants.KeyDataFormatPem)
        else:
            key = xmlsec.Key.from_memory(key_data, xmlsec.constants.KeyDataFormatDer)
        
        # Load certificate if available
        if self.signing_cert_path:
            with open(self.signing_cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                if b'-----BEGIN' in cert_data:
                    key.load_cert_from_memory(cert_data, xmlsec.constants.KeyDataFormatPem)
        
        # Create signature template using xmlsec.template
        signature_node = xmlsec.template.create(
            header,
            xmlsec.constants.TransformExclC14N,
            xmlsec.constants.TransformRsaSha1
        )
        
        # Add reference to Body
        ref = xmlsec.template.add_reference(
            signature_node,
            xmlsec.constants.TransformSha1,
            uri=f"#{body_id}"
        )
        
        # Add enveloped transform
        xmlsec.template.add_transform(ref, xmlsec.constants.TransformExclC14N)
        
        # Add KeyInfo with X509 data
        key_info = xmlsec.template.ensure_key_info(signature_node)
        x509_data = xmlsec.template.add_x509_data(key_info)
        xmlsec.template.x509_data_add_issuer_serial(x509_data)
        xmlsec.template.x509_data_add_certificate(x509_data)
        
        # Sign the document
        ctx = xmlsec.SignatureContext()
        ctx.key = key
        
        ctx.sign(signature_node)
        
        print("Envelope signed successfully")
        return envelope
    
    def _encrypt_body(self, envelope):
        """Encrypt SOAP Body using XML Encryption"""
        try:
            import xmlsec
        except ImportError:
            raise ImportError("xmlsec library is required for encryption. Install: pip install xmlsec")
        
        if not self.encryption_cert_path:
            raise ValueError("Encryption certificate path is required for encrypting requests")
        
        print("Encrypting SOAP body...")
        
        # Namespaces
        SOAPENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
        
        # Get the Body element
        body = envelope.find(f"{{{SOAPENV_NS}}}Body")
        if body is None:
            raise ValueError("SOAP Body not found")
        
        # Load encryption certificate (server's public key)
        with open(self.encryption_cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()
        
        if b'-----BEGIN CERTIFICATE-----' in cert_data:
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        else:
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
        
        # Get public key
        public_key = cert.public_key()
        
        # Serialize public key for xmlsec
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Create key from public key
        key = xmlsec.Key.from_memory(public_key_pem, xmlsec.constants.KeyDataFormatPem)
        
        # Create encryption template properly with sign_method parameter
        enc_data = xmlsec.template.create(
            envelope,
            xmlsec.constants.TransformAes128Cbc,
            type=xmlsec.constants.TypeEncContent,
            sign_method=xmlsec.constants.TransformRsaPkcs1  # FIX: Added sign_method
        )
        
        # Ensure KeyInfo
        key_info = xmlsec.template.ensure_key_info(enc_data)
        
        # Add EncryptedKey
        enc_key = xmlsec.template.add_encrypted_key(
            key_info,
            xmlsec.constants.TransformRsaPkcs1
        )
        
        # Add KeyInfo to EncryptedKey
        key_info2 = xmlsec.template.ensure_key_info(enc_key)
        
        # Serialize body content
        body_content = etree.tostring(body)
        
        # Encrypt
        enc_ctx = xmlsec.EncryptionContext()
        enc_ctx.key = key
        
        encrypted_data = enc_ctx.encrypt_binary(body_content, enc_data)
        
        # Replace body with encrypted data
        parent = body.getparent()
        parent.replace(body, encrypted_data)
        
        print("Body encrypted successfully")
        return envelope
    
    def send_request(self, operation_name, **kwargs):
        """
        Send SOAP request with WS-Security and mTLS
        
        Args:
            operation_name: SOAP operation name
            **kwargs: Operation parameters
            
        Returns:
            SOAP response
        """
        # Create Zeep client with custom transport
        transport = Transport(session=self.session)
        settings = Settings(strict=False, xml_huge_tree=True)
        
        client = Client(
            wsdl=self.wsdl_url,
            transport=transport,
            settings=settings
        )
        
        # Override endpoint if specified
        if self.endpoint_url:
            service = client.create_service(
                '{http://xmlns.example.com/unique/default/namespace/1115236122168}ClientSearchRequestBinding',
                self.endpoint_url
            )
        else:
            service = client.service
        
        # Get the operation
        operation = getattr(service, operation_name)
        
        # Execute the request
        response = operation(**kwargs)
        
        return response
    
    def send_raw_xml_request(self, xml_content):
        """
        Send raw XML SOAP request with WS-Security headers
        
        Args:
            xml_content: Raw XML content (string or bytes)
            
        Returns:
            Response object
        """
        # Parse XML
        if isinstance(xml_content, str):
            xml_content = xml_content.encode('utf-8')
        
        envelope = etree.fromstring(xml_content)
        
        # Add security header (timestamp, certificate)
        envelope = self._create_security_header(envelope)
        
        # Encrypt body if requested
        if self.encrypt_request:
            try:
                envelope = self._encrypt_body(envelope)
            except Exception as e:
                print(f"Warning: Encryption failed: {e}")
                import traceback
                traceback.print_exc()
                print("Sending unencrypted request...")
        
        # Sign envelope if requested (after encryption)
        if self.sign_request:
            try:
                envelope = self._sign_envelope(envelope)
            except Exception as e:
                print(f"Warning: Signing failed: {e}")
                import traceback
                traceback.print_exc()
                print("Sending unsigned request...")
        
        # Convert back to string
        request_xml = etree.tostring(envelope, pretty_print=True)
        
        # Debug: Print the request
        print("=" * 80)
        print("FINAL REQUEST:")
        print(request_xml.decode('utf-8'))
        print("=" * 80)
        
        # Send request
        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': ''
        }
        
        response = self.session.post(
            self.endpoint_url,
            data=request_xml,
            headers=headers
        )
        
        return response
    
    def decrypt_response(self, response_xml):
        """
        Decrypt encrypted SOAP response using xmlsec - FIXED VERSION
        
        Args:
            response_xml: Encrypted response XML (string or bytes)
            
        Returns:
            Decrypted XML element tree
        """
        try:
            import xmlsec
        except ImportError:
            raise ImportError("xmlsec library is required for decryption. Install: pip install xmlsec")
        
        if isinstance(response_xml, bytes):
            try:
                response_xml = response_xml.decode('utf-8')
            except UnicodeDecodeError:
                response_xml = response_xml.decode('latin-1')
        
        # Parse response
        try:
            # Parse into a document (not just element)
            parser = etree.XMLParser(remove_blank_text=True)
            root = etree.fromstring(response_xml.encode('utf-8'), parser)
        except etree.XMLSyntaxError as e:
            print(f"XML parsing error: {e}")
            print(f"Response preview: {response_xml[:500]}")
            raise
        
        # Look for EncryptedData elements
        XENC_NS = "http://www.w3.org/2001/04/xmlenc#"
        encrypted_elements = root.findall(f".//{{{XENC_NS}}}EncryptedData")
        
        if not encrypted_elements:
            print("No encrypted data found in response.")
            return root
        
        print(f"Found {len(encrypted_elements)} encrypted element(s). Decrypting...")
        
        # Load the private key for decryption
        if not self.client_key_path:
            raise ValueError("Client private key path is required for decryption")
        
        # Load private key
        try:
            with open(self.client_key_path, 'rb') as key_file:
                key_data = key_file.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"Private key file not found: {self.client_key_path}")
        
        # Create key manager
        manager = xmlsec.KeysManager()
        
        # Load the key
        try:
            if b'-----BEGIN' in key_data:
                key = xmlsec.Key.from_memory(key_data, xmlsec.constants.KeyDataFormatPem)
            else:
                key = xmlsec.Key.from_memory(key_data, xmlsec.constants.KeyDataFormatDer)
        except Exception as e:
            raise ValueError(f"Failed to load private key: {e}")
        
        # Set key name for lookup (important!)
        key.name = "decryption-key"
        
        # If we have a certificate, load it
        if self.encryption_cert_path:
            try:
                with open(self.encryption_cert_path, 'rb') as cert_file:
                    cert_data = cert_file.read()
                    if b'-----BEGIN' in cert_data:
                        key.load_cert_from_memory(cert_data, xmlsec.constants.KeyDataFormatPem)
                    else:
                        key.load_cert_from_memory(cert_data, xmlsec.constants.KeyDataFormatDer)
            except Exception as e:
                print(f"Warning: Could not load certificate: {e}")
        
        # Add key to manager
        manager.add_key(key)
        
        # Decrypt each encrypted element
        for idx, encrypted_element in enumerate(encrypted_elements):
            try:
                print(f"Decrypting element {idx + 1}/{len(encrypted_elements)}...")
                
                # Show encryption method
                enc_method = encrypted_element.find(f".//{{{XENC_NS}}}EncryptionMethod")
                if enc_method is not None:
                    algorithm = enc_method.get("Algorithm")
                    print(f"Encryption algorithm: {algorithm}")
                
                # Create encryption context with manager
                enc_ctx = xmlsec.EncryptionContext(manager)
                
                # CRITICAL FIX: Set the key directly on context
                enc_ctx.key = key
                
                # Decrypt - this modifies tree in place
                enc_ctx.decrypt(encrypted_element)
                
                print(f"Successfully decrypted element {idx + 1}")
                
            except Exception as e:
                error_msg = str(e)
                print(f"Error decrypting element {idx + 1}: {error_msg}")
                
                # Check for specific error types
                if "failed to decrypt" in error_msg.lower():
                    print("Possible causes:")
                    print("  1. Wrong private key (doesn't match public key used for encryption)")
                    print("  2. Incorrect encryption algorithm support")
                    print("  3. Missing key in KeysManager")
                    print(f"  4. Key name mismatch")
                
                # Show element structure for debugging
                print(f"Element structure:")
                print(etree.tostring(encrypted_element, pretty_print=True).decode()[:500])
                
                # Don't raise, continue with other elements
                continue
        
        return root
