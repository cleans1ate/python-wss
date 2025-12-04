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
                 signing_key_path=None):
        """
        Initialize the WSSE mTLS client
        
        Args:
            wsdl_url: WSDL service URL
            endpoint_url: Actual endpoint URL
            client_cert_path: Path to client certificate for mTLS (.crt or .pem)
            client_key_path: Path to client private key for mTLS (.key or .pem)
            server_cert_path: Path to server CA certificate (optional)
            encryption_cert_path: Path to encryption certificate (.crt)
            signing_cert_path: Path to signing certificate (.crt)
            signing_key_path: Path to signing private key (.key)
        """
        self.wsdl_url = wsdl_url
        self.endpoint_url = endpoint_url
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self.server_cert_path = server_cert_path
        self.encryption_cert_path = encryption_cert_path
        self.signing_cert_path = signing_cert_path
        self.signing_key_path = signing_key_path
        
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
        """Create WS-Security header with encryption and signature"""
        
        # Namespaces
        SOAPENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
        WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
        XENC_NS = "http://www.w3.org/2001/04/xmlenc#"
        DS_NS = "http://www.w3.org/2000/09/xmldsig#"
        
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
        
        # Add security header
        envelope_with_security = self._create_security_header(envelope)
        
        # Convert back to string
        request_xml = etree.tostring(envelope_with_security, pretty_print=True)
        
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
        Decrypt encrypted SOAP response using xmlsec
        
        Args:
            response_xml: Encrypted response XML (string or bytes)
            
        Returns:
            Decrypted XML element tree
        """
        import xmlsec
        
        if isinstance(response_xml, bytes):
            response_xml = response_xml.decode('utf-8')
        
        # Parse response
        root = etree.fromstring(response_xml.encode('utf-8'))
        
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
        with open(self.client_key_path, 'rb') as key_file:
            key_data = key_file.read()
        
        # Create key manager
        key_manager = xmlsec.KeysManager()
        
        # Load the key
        if b'-----BEGIN' in key_data:
            # PEM format
            key = xmlsec.Key.from_memory(key_data, xmlsec.constants.KeyDataFormatPem)
        else:
            # DER format
            key = xmlsec.Key.from_memory(key_data, xmlsec.constants.KeyDataFormatDer)
        
        # If we have a certificate, load it too
        if self.encryption_cert_path:
            with open(self.encryption_cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                key.load_cert_from_memory(cert_data, xmlsec.constants.KeyDataFormatPem)
        
        # Add key to manager
        key_manager.add_key(key)
        
        # Decrypt each encrypted element
        for encrypted_element in encrypted_elements:
            try:
                # Create encryption context
                enc_ctx = xmlsec.EncryptionContext(key_manager)
                
                # Decrypt the element
                decrypted_data = enc_ctx.decrypt(encrypted_element)
                
                # Replace encrypted element with decrypted content
                parent = encrypted_element.getparent()
                if parent is not None:
                    # Parse decrypted data
                    decrypted_tree = etree.fromstring(decrypted_data)
                    
                    # Replace the EncryptedData element with decrypted content
                    parent.replace(encrypted_element, decrypted_tree)
                    print("Successfully decrypted element")
                
            except Exception as e:
                print(f"Error decrypting element: {e}")
                # Try alternative decryption method
                try:
                    self._decrypt_element_alternative(encrypted_element, key_manager)
                except Exception as e2:
                    print(f"Alternative decryption also failed: {e2}")
                    raise
        
        return root
    
    def _decrypt_element_alternative(self, encrypted_element, key_manager):
        """
        Alternative decryption method for different encryption formats
        
        Args:
            encrypted_element: EncryptedData XML element
            key_manager: xmlsec KeysManager
        """
        import xmlsec
        
        # Try to decrypt using the parent document
        enc_ctx = xmlsec.EncryptionContext(key_manager)
        
        # Get the entire document
        doc = encrypted_element.getroottree()
        
        # Find and decrypt
        enc_ctx.decrypt(encrypted_element)
        
        print("Alternative decryption successful")
