"""
Complete WSSE SOAP Client with XML Encryption, Signing, and mTLS
Uses xmlsec for proper WS-Security implementation
"""

import requests
from lxml import etree
import xmlsec
import base64
from datetime import datetime, timedelta
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class CompleteWSSEClient:
    """Complete WSSE client with encryption, signing, and mTLS"""
    
    # Namespaces
    NSMAP = {
        'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
        'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
        'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
        'xenc': 'http://www.w3.org/2001/04/xmlenc#',
        'ns1': 'http://xmlns.example.com/unique/default/namespace/1115236122168'
    }
    
    def __init__(self, endpoint_url, client_cert, client_key, 
                 encryption_cert, signing_cert, signing_key, 
                 server_ca=None, verify_ssl=True):
        """
        Initialize Complete WSSE Client
        
        Args:
            endpoint_url: SOAP endpoint URL
            client_cert: Client certificate path for mTLS
            client_key: Client private key path for mTLS
            encryption_cert: Public certificate for encrypting request
            signing_cert: Certificate for signing
            signing_key: Private key for signing
            server_ca: Server CA certificate (optional)
            verify_ssl: Whether to verify SSL (default True)
        """
        self.endpoint_url = endpoint_url
        self.client_cert = client_cert
        self.client_key = client_key
        self.encryption_cert = encryption_cert
        self.signing_cert = signing_cert
        self.signing_key = signing_key
        self.server_ca = server_ca
        self.verify_ssl = verify_ssl
        
        # Load certificates
        self._load_certificates()
        
    def _load_certificates(self):
        """Load and parse certificates"""
        # Load signing certificate
        with open(self.signing_cert, 'rb') as f:
            cert_data = f.read()
            if b'-----BEGIN CERTIFICATE-----' in cert_data:
                self.sign_cert_obj = x509.load_pem_x509_certificate(cert_data, default_backend())
            else:
                self.sign_cert_obj = x509.load_der_x509_certificate(cert_data, default_backend())
        
        # Load encryption certificate
        with open(self.encryption_cert, 'rb') as f:
            cert_data = f.read()
            if b'-----BEGIN CERTIFICATE-----' in cert_data:
                self.enc_cert_obj = x509.load_pem_x509_certificate(cert_data, default_backend())
            else:
                self.enc_cert_obj = x509.load_der_x509_certificate(cert_data, default_backend())
    
    def create_plain_request(self, channel_ind, cif_static_key, client_search_type,
                            business_client_name='', city='', state='', zip_code='', ssn_tin=''):
        """Create plain SOAP request (before encryption)"""
        
        # Create SOAP envelope
        envelope = etree.Element(
            f"{{{self.NSMAP['soapenv']}}}Envelope",
            nsmap={'soapenv': self.NSMAP['soapenv'], 'ns1': self.NSMAP['ns1']}
        )
        
        header = etree.SubElement(envelope, f"{{{self.NSMAP['soapenv']}}}Header")
        body = etree.SubElement(envelope, f"{{{self.NSMAP['soapenv']}}}Body")
        
        # Add request content
        search_request = etree.SubElement(body, f"{{{self.NSMAP['ns1']}}}ClientSearchRequest")
        
        elements = {
            'ChannelInd': channel_ind,
            'CIFStaticKey': cif_static_key,
            'ClientSearchType': client_search_type,
            'BusinessClientName': business_client_name,
            'City': city,
            'State': state,
            'ZIP': zip_code,
            'SSN-TIN': ssn_tin
        }
        
        for elem_name, elem_value in elements.items():
            if elem_value:  # Only add non-empty values
                elem = etree.SubElement(search_request, f"{{{self.NSMAP['ns1']}}}{elem_name}")
                elem.text = elem_value
        
        return envelope
    
    def add_wsse_header(self, envelope):
        """Add WS-Security header with timestamp and binary security token"""
        
        header = envelope.find(f".//{{{self.NSMAP['soapenv']}}}Header")
        if header is None:
            header = etree.Element(f"{{{self.NSMAP['soapenv']}}}Header")
            envelope.insert(0, header)
        
        # Create Security element
        security = etree.SubElement(
            header,
            f"{{{self.NSMAP['wsse']}}}Security",
            nsmap={'wsse': self.NSMAP['wsse'], 'wsu': self.NSMAP['wsu']}
        )
        security.set(f"{{{self.NSMAP['soapenv']}}}mustUnderstand", "1")
        
        # Add Timestamp
        timestamp_id = f"TS-{uuid.uuid4().hex}"
        timestamp = etree.SubElement(security, f"{{{self.NSMAP['wsu']}}}Timestamp")
        timestamp.set(f"{{{self.NSMAP['wsu']}}}Id", timestamp_id)
        
        created = etree.SubElement(timestamp, f"{{{self.NSMAP['wsu']}}}Created")
        created.text = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        
        expires = etree.SubElement(timestamp, f"{{{self.NSMAP['wsu']}}}Expires")
        expires.text = (datetime.utcnow() + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        
        # Add BinarySecurityToken
        cert_der = self.sign_cert_obj.public_bytes(serialization.Encoding.DER)
        cert_b64 = base64.b64encode(cert_der).decode('utf-8')
        
        bst_id = f"X509-{uuid.uuid4().hex}"
        bst = etree.SubElement(security, f"{{{self.NSMAP['wsse']}}}BinarySecurityToken")
        bst.set("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
        bst.set("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
        bst.set(f"{{{self.NSMAP['wsu']}}}Id", bst_id)
        bst.text = cert_b64
        
        return envelope, security, bst_id, timestamp_id
    
    def sign_message(self, envelope, security, bst_id, timestamp_id):
        """Sign the SOAP message using xmlsec"""
        
        # Create Signature element
        signature = xmlsec.template.create(
            envelope,
            xmlsec.constants.TransformExclC14N,
            xmlsec.constants.TransformRsaSha1
        )
        
        security.append(signature)
        
        # Add reference to Body
        body = envelope.find(f".//{{{self.NSMAP['soapenv']}}}Body")
        body_id = body.get(f"{{{self.NSMAP['wsu']}}}Id")
        if not body_id:
            body_id = f"Body-{uuid.uuid4().hex}"
            body.set(f"{{{self.NSMAP['wsu']}}}Id", body_id)
        
        ref = xmlsec.template.add_reference(
            signature,
            xmlsec.constants.TransformSha1,
            uri=f"#{body_id}"
        )
        xmlsec.template.add_transform(ref, xmlsec.constants.TransformExclC14N)
        
        # Add reference to Timestamp
        ref_ts = xmlsec.template.add_reference(
            signature,
            xmlsec.constants.TransformSha1,
            uri=f"#{timestamp_id}"
        )
        xmlsec.template.add_transform(ref_ts, xmlsec.constants.TransformExclC14N)
        
        # Add KeyInfo
        key_info = xmlsec.template.ensure_key_info(signature)
        sec_token_ref = etree.SubElement(
            key_info,
            f"{{{self.NSMAP['wsse']}}}SecurityTokenReference"
        )
        wsse_ref = etree.SubElement(
            sec_token_ref,
            f"{{{self.NSMAP['wsse']}}}Reference"
        )
        wsse_ref.set("URI", f"#{bst_id}")
        wsse_ref.set("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
        
        # Sign the document
        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_file(self.signing_key, xmlsec.constants.KeyDataFormatPem)
        ctx.key = key
        
        ctx.sign(signature)
        
        return envelope
    
    def encrypt_body(self, envelope):
        """Encrypt SOAP body using xmlsec"""
        
        body = envelope.find(f".//{{{self.NSMAP['soapenv']}}}Body")
        
        # Create encryption template
        enc_data = xmlsec.template.encrypted_data_create(
            envelope,
            xmlsec.constants.TransformAes128Cbc,
            type=xmlsec.constants.TypeEncElement,
            ns="xenc"
        )
        
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_data)
        
        key_info = xmlsec.template.encrypted_data_ensure_key_info(enc_data, ns="dsig")
        enc_key = xmlsec.template.add_encrypted_key(
            key_info,
            xmlsec.constants.TransformRsaOaep
        )
        xmlsec.template.encrypted_data_ensure_cipher_value(enc_key)
        
        # Encrypt
        manager = xmlsec.KeysManager()
        manager.add_key(xmlsec.Key.from_file(self.encryption_cert, xmlsec.constants.KeyDataFormatCertPem))
        
        enc_ctx = xmlsec.EncryptionContext(manager)
        enc_ctx.key = xmlsec.Key.generate(xmlsec.constants.KeyDataAes, 128, xmlsec.constants.KeyDataTypeSession)
        
        encrypted = enc_ctx.encrypt_xml(enc_data, body)
        
        return envelope
    
    def send_request(self, channel_ind, cif_static_key, client_search_type,
                    business_client_name='', city='', state='', zip_code='', ssn_tin=''):
        """
        Create, sign, encrypt and send SOAP request
        
        Returns:
            Response object
        """
        # Create plain request
        envelope = self.create_plain_request(
            channel_ind, cif_static_key, client_search_type,
            business_client_name, city, state, zip_code, ssn_tin
        )
        
        print("1. Plain request created")
        
        # Add WSSE header
        envelope, security, bst_id, timestamp_id = self.add_wsse_header(envelope)
        print("2. WSSE header added")
        
        # Sign message
        envelope = self.sign_message(envelope, security, bst_id, timestamp_id)
        print("3. Message signed")
        
        # Encrypt body
        envelope = self.encrypt_body(envelope)
        print("4. Body encrypted")
        
        # Convert to string
        request_xml = etree.tostring(envelope, pretty_print=True, xml_declaration=True, encoding='UTF-8')
        
        # Send request with mTLS
        session = requests.Session()
        session.cert = (self.client_cert, self.client_key)
        session.verify = self.server_ca if self.server_ca else self.verify_ssl
        
        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': ''
        }
        
        print(f"5. Sending request to {self.endpoint_url}")
        response = session.post(
            self.endpoint_url,
            data=request_xml,
            headers=headers,
            timeout=30
        )
        
        print(f"6. Response received: {response.status_code}")
        return response
    
    def decrypt_response(self, response_xml):
        """Decrypt encrypted SOAP response"""
        
        if isinstance(response_xml, bytes):
            response_xml = response_xml.decode('utf-8')
        
        root = etree.fromstring(response_xml.encode('utf-8'))
        
        # Find encrypted data
        enc_data = root.find(f".//{{{self.NSMAP['xenc']}}}EncryptedData")
        
        if enc_data is not None:
            print("Response is encrypted, decrypting...")
            
            # Decrypt
            manager = xmlsec.KeysManager()
            manager.add_key(xmlsec.Key.from_file(self.signing_key, xmlsec.constants.KeyDataFormatPem))
            
            enc_ctx = xmlsec.EncryptionContext(manager)
            decrypted = enc_ctx.decrypt(enc_data)
            
            return decrypted
        else:
            print("Response is not encrypted")
            return root


# Example Usage
def main():
    """Example usage"""
    
    # Configuration - UPDATE THESE PATHS
    ENDPOINT_URL = "https://your-endpoint.com/service"
    CLIENT_CERT = "certs/client_cert.pem"
    CLIENT_KEY = "certs/client_key.pem"
    ENCRYPTION_CERT = "certs/encryption_cert.pem"
    SIGNING_CERT = "certs/signing_cert.pem"
    SIGNING_KEY = "certs/signing_key.pem"
    SERVER_CA = "certs/server_ca.pem"  # Optional
    
    # Create client
    client = CompleteWSSEClient(
        endpoint_url=ENDPOINT_URL,
        client_cert=CLIENT_CERT,
        client_key=CLIENT_KEY,
        encryption_cert=ENCRYPTION_CERT,
        signing_cert=SIGNING_CERT,
        signing_key=SIGNING_KEY,
        server_ca=SERVER_CA,
        verify_ssl=True
    )
    
    # Send request
    try:
        response = client.send_request(
            channel_ind='MOB',
            cif_static_key='88462327',
            client_search_type='X01'
        )
        
        print(f"\nStatus Code: {response.status_code}")
        print(f"Response Headers: {response.headers}")
        
        # Decrypt response
        decrypted = client.decrypt_response(response.content)
        print("\nDecrypted Response:")
        print(etree.tostring(decrypted, pretty_print=True).decode())
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
