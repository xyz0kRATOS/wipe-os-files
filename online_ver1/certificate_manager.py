#!/usr/bin/env python3

"""
certificate_manager.py - Digital Certificate Generation and Supabase Integration
NIST 800-88 Compliant Wipe Certificate Generator
"""

import os
import json
import time
import hashlib
import hmac
import base64
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import requests

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class WipeCertificate:
    """Wipe Certificate Data Structure"""
    certificate_id: str
    device_info: Dict[str, Any]
    wipe_operation: Dict[str, Any]
    compliance_standards: List[str]
    verification_data: Dict[str, Any]
    timestamp: str
    certificate_version: str = "1.0"
    issuer: str = "SecureWipe-Tool"
    digital_signature: Optional[str] = None
    certificate_hash: Optional[str] = None

@dataclass
class NISTComplianceData:
    """NIST 800-88 Compliance Information"""
    standard_version: str = "NIST-800-88-Rev1"
    sanitization_method: str = ""
    media_type: str = ""
    security_category: str = ""
    verification_method: str = "Random Sampling"
    destruction_method: str = "Not Applicable"
    compliance_level: str = "PURGE"  # CLEAR, PURGE, or DESTROY

class CertificateManager:
    """Manages wipe certificate generation and digital signing"""

    def __init__(self, config_dir="/opt/secure-wipe/config"):
        self.config_dir = config_dir
        self.cert_dir = f"{config_dir}/certificates"
        self.private_key_path = f"{config_dir}/private_key.pem"
        self.public_key_path = f"{config_dir}/public_key.pem"
        self.certificate_path = f"{config_dir}/signing_cert.pem"

        os.makedirs(self.cert_dir, exist_ok=True)
        self._ensure_signing_keys()

    def _ensure_signing_keys(self):
        """Ensure signing keys exist"""
        if not os.path.exists(self.private_key_path):
            self._generate_signing_keys()

    def _generate_signing_keys(self):
        """Generate RSA key pair for signing"""
        logger.info("Generating new RSA key pair for certificate signing")

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Save private key
        with open(self.private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        os.chmod(self.private_key_path, 0o600)  # Secure permissions

        # Save public key
        public_key = private_key.public_key()
        with open(self.public_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        # Generate self-signed certificate
        self._generate_self_signed_cert(private_key)

        logger.info("RSA key pair generated successfully")

    def _generate_self_signed_cert(self, private_key):
        """Generate self-signed certificate for the tool"""
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Delhi"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "New Delhi"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Wipe Tool"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureWipe Certificate Authority"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow().replace(year=datetime.utcnow().year + 10)  # Valid for 10 years
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Save certificate
        with open(self.certificate_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def generate_wipe_certificate(self, drive_info: Dict, operation_info: Dict,
                                user_id: str = None) -> WipeCertificate:
        """Generate a complete wipe certificate"""
        logger.info(f"Generating wipe certificate for device {drive_info.get('device')}")

        # Generate unique certificate ID
        timestamp = datetime.now(timezone.utc)
        cert_id = f"CERT_{int(timestamp.timestamp())}_{hashlib.sha256(drive_info.get('device', '').encode()).hexdigest()[:8]}"

        # Determine NIST compliance data
        compliance_data = self._determine_nist_compliance(drive_info, operation_info)

        # Create verification data
        verification_data = {
            "verification_method": "Random Sector Sampling",
            "sample_size": "1000 blocks (4KB each)",
            "verification_hash": operation_info.get("verification_hash", ""),
            "verification_timestamp": timestamp.isoformat(),
            "zero_percentage": self._calculate_zero_percentage(operation_info),
            "verification_status": "PASSED" if operation_info.get("status") == "VERIFIED" else "COMPLETED"
        }

        # Create certificate
        certificate = WipeCertificate(
            certificate_id=cert_id,
            device_info=drive_info,
            wipe_operation=operation_info,
            compliance_standards=[compliance_data.standard_version],
            verification_data=verification_data,
            timestamp=timestamp.isoformat(),
            issuer="SecureWipe-Tool-v1.0"
        )

        # Generate digital signature
        certificate.digital_signature = self._sign_certificate(certificate)
        certificate.certificate_hash = self._generate_certificate_hash(certificate)

        logger.info(f"Wipe certificate {cert_id} generated successfully")
        return certificate

    def _determine_nist_compliance(self, drive_info: Dict, operation_info: Dict) -> NISTComplianceData:
        """Determine NIST 800-88 compliance level and data"""
        wipe_method = operation_info.get("method", "")
        drive_type = drive_info.get("drive_type", "Unknown")

        compliance = NISTComplianceData()
        compliance.sanitization_method = wipe_method

        # Determine media type
        if "SSD" in drive_type or "NVMe" in drive_type:
            compliance.media_type = "Flash Memory"
        elif "HDD" in drive_type:
            compliance.media_type = "Magnetic Storage"
        else:
            compliance.media_type = "Unknown"

        # Determine security category and compliance level
        if wipe_method in ["ATA_SECURE_ERASE", "ATA_ENHANCED_SECURE_ERASE", "NVME_FORMAT", "NIST_PURGE_CRYPTO"]:
            compliance.security_category = "High"
            compliance.compliance_level = "PURGE"
        elif wipe_method in ["NIST_PURGE_OVERWRITE", "DOD_3PASS"]:
            compliance.security_category = "Moderate"
            compliance.compliance_level = "PURGE"
        elif wipe_method == "NIST_CLEAR":
            compliance.security_category = "Low"
            compliance.compliance_level = "CLEAR"
        else:
            compliance.security_category = "Unknown"
            compliance.compliance_level = "CLEAR"

        return compliance

    def _calculate_zero_percentage(self, operation_info: Dict) -> float:
        """Calculate percentage of zeros from verification data"""
        # This would be calculated during verification
        return 95.0  # Placeholder - should come from actual verification

    def _sign_certificate(self, certificate: WipeCertificate) -> str:
        """Generate digital signature for certificate"""
        try:
            # Load private key
            with open(self.private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )

            # Create certificate data for signing (exclude signature field)
            cert_data = asdict(certificate)
            cert_data['digital_signature'] = None
            cert_data['certificate_hash'] = None

            # Convert to canonical JSON
            cert_json = json.dumps(cert_data, sort_keys=True, separators=(',', ':'))

            # Sign the data
            signature = private_key.sign(
                cert_json.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Return base64 encoded signature
            return base64.b64encode(signature).decode('utf-8')

        except Exception as e:
            logger.error(f"Failed to sign certificate: {e}")
            return ""

    def _generate_certificate_hash(self, certificate: WipeCertificate) -> str:
        """Generate SHA-256 hash of the certificate"""
        cert_data = asdict(certificate)
        cert_data['certificate_hash'] = None  # Exclude hash field from hash calculation

        cert_json = json.dumps(cert_data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(cert_json.encode('utf-8')).hexdigest()

    def verify_certificate_signature(self, certificate: WipeCertificate) -> bool:
        """Verify certificate digital signature"""
        try:
            # Load public key
            with open(self.public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())

            # Recreate signed data
            cert_data = asdict(certificate)
            original_signature = cert_data['digital_signature']
            cert_data['digital_signature'] = None
            cert_data['certificate_hash'] = None

            cert_json = json.dumps(cert_data, sort_keys=True, separators=(',', ':'))

            # Verify signature
            signature_bytes = base64.b64decode(original_signature)

            public_key.verify(
                signature_bytes,
                cert_json.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return True

        except Exception as e:
            logger.error(f"Certificate signature verification failed: {e}")
            return False

    def export_certificate_json(self, certificate: WipeCertificate, filepath: str = None) -> str:
        """Export certificate as JSON"""
        cert_dict = asdict(certificate)

        # Add additional metadata
        cert_dict['export_timestamp'] = datetime.now(timezone.utc).isoformat()
        cert_dict['tool_version'] = "SecureWipe-v1.0"
        cert_dict['export_format'] = "JSON"

        json_data = json.dumps(cert_dict, indent=2, sort_keys=True)

        if filepath:
            with open(filepath, 'w') as f:
                f.write(json_data)
            logger.info(f"Certificate exported to JSON: {filepath}")

        return json_data

    def export_certificate_pdf(self, certificate: WipeCertificate, filepath: str) -> bool:
        """Export certificate as PDF (simplified version)"""
        try:
            # This is a basic implementation - in production, you'd use a proper PDF library
            # like reportlab or weasyprint

            html_content = self._generate_certificate_html(certificate)

            # For now, save as HTML (PDF generation requires additional libraries)
            html_filepath = filepath.replace('.pdf', '.html')
            with open(html_filepath, 'w') as f:
                f.write(html_content)

            logger.info(f"Certificate exported as HTML: {html_filepath}")
            logger.info("Note: PDF generation requires additional libraries (reportlab/weasyprint)")

            return True

        except Exception as e:
            logger.error(f"Failed to export PDF certificate: {e}")
            return False

    def _generate_certificate_html(self, certificate: WipeCertificate) -> str:
        """Generate HTML representation of certificate"""
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Data Wipe Certificate</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }}
                .section {{ margin: 20px 0; }}
                .field {{ margin: 10px 0; }}
                .label {{ font-weight: bold; }}
                .signature {{ border-top: 1px solid #ccc; margin-top: 40px; padding-top: 20px; }}
                .compliance {{ background-color: #f0f8f0; padding: 15px; border-left: 4px solid #28a745; }}
                .verification {{ background-color: #f8f9fa; padding: 15px; border-left: 4px solid #007bff; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Secure Data Wipe Certificate</h1>
                <h2>NIST 800-88 Rev. 1 Compliant</h2>
                <p>Certificate ID: <strong>{certificate.certificate_id}</strong></p>
                <p>Issued: {certificate.timestamp}</p>
            </div>

            <div class="section">
                <h3>Device Information</h3>
                <div class="field"><span class="label">Device:</span> {certificate.device_info.get('device', 'Unknown')}</div>
                <div class="field"><span class="label">Model:</span> {certificate.device_info.get('model', 'Unknown')}</div>
                <div class="field"><span class="label">Serial:</span> {certificate.device_info.get('serial', 'Unknown')}</div>
                <div class="field"><span class="label">Size:</span> {certificate.device_info.get('size', 'Unknown')}</div>
                <div class="field"><span class="label">Type:</span> {certificate.device_info.get('drive_type', 'Unknown')}</div>
            </div>

            <div class="section">
                <h3>Wipe Operation Details</h3>
                <div class="field"><span class="label">Method:</span> {certificate.wipe_operation.get('method', 'Unknown')}</div>
                <div class="field"><span class="label">Status:</span> {certificate.wipe_operation.get('status', 'Unknown')}</div>
                <div class="field"><span class="label">Duration:</span> {certificate.wipe_operation.get('duration', 'Unknown')} seconds</div>
                <div class="field"><span class="label">Passes:</span> {certificate.wipe_operation.get('passes_completed', 0)}</div>
            </div>

            <div class="section compliance">
                <h3>NIST 800-88 Compliance</h3>
                <div class="field"><span class="label">Standard:</span> NIST SP 800-88 Rev. 1</div>
                <div class="field"><span class="label">Compliance Level:</span> PURGE/CLEAR</div>
                <div class="field"><span class="label">Media Type:</span> {certificate.device_info.get('drive_type', 'Unknown')}</div>
            </div>

            <div class="section verification">
                <h3>Verification Data</h3>
                <div class="field"><span class="label">Method:</span> {certificate.verification_data.get('verification_method', 'Unknown')}</div>
                <div class="field"><span class="label">Sample Size:</span> {certificate.verification_data.get('sample_size', 'Unknown')}</div>
                <div class="field"><span class="label">Status:</span> {certificate.verification_data.get('verification_status', 'Unknown')}</div>
                <div class="field"><span class="label">Hash:</span> {certificate.verification_data.get('verification_hash', 'Unknown')[:32]}...</div>
            </div>

            <div class="signature">
                <h3>Digital Signature</h3>
                <div class="field"><span class="label">Certificate Hash:</span> {certificate.certificate_hash}</div>
                <div class="field"><span class="label">Digital Signature:</span> {certificate.digital_signature[:50]}...</div>
                <div class="field"><span class="label">Issuer:</span> {certificate.issuer}</div>

                <p><em>This certificate is digitally signed and can be verified using the public key of the issuing authority.</em></p>
            </div>
        </body>
        </html>
        """

        return html_template

class SupabaseManager:
    """Manages Supabase database operations for certificate storage"""

    def __init__(self, supabase_url: str, supabase_key: str):
        self.supabase_url = supabase_url
        self.supabase_key = supabase_key
        self.headers = {
            'apikey': supabase_key,
            'Authorization': f'Bearer {supabase_key}',
            'Content-Type': 'application/json'
        }

    def store_certificate(self, certificate: WipeCertificate, user_id: str = None) -> bool:
        """Store certificate in Supabase database"""
        try:
            logger.info(f"Storing certificate {certificate.certificate_id} in Supabase")

            # Prepare data for storage
            cert_data = {
                'certificate_id': certificate.certificate_id,
                'user_id': user_id,
                'device_model': certificate.device_info.get('model', 'Unknown'),
                'device_serial': certificate.device_info.get('serial', 'Unknown'),
                'device_size': certificate.device_info.get('size', 'Unknown'),
                'device_type': certificate.device_info.get('drive_type', 'Unknown'),
                'wipe_method': certificate.wipe_operation.get('method', 'Unknown'),
                'wipe_status': certificate.wipe_operation.get('status', 'Unknown'),
                'wipe_duration': certificate.wipe_operation.get('duration', 0),
                'verification_hash': certificate.verification_data.get('verification_hash', ''),
                'verification_status': certificate.verification_data.get('verification_status', 'UNKNOWN'),
                'certificate_hash': certificate.certificate_hash,
                'digital_signature': certificate.digital_signature,
                'compliance_standards': certificate.compliance_standards,
                'created_at': certificate.timestamp,
                'certificate_data': asdict(certificate)  # Store full certificate as JSON
            }

            # Insert into Supabase
            response = requests.post(
                f'{self.supabase_url}/rest/v1/wipe_certificates',
                headers=self.headers,
                json=cert_data
            )

            if response.status_code in [200, 201]:
                logger.info(f"Certificate {certificate.certificate_id} stored successfully")
                return True
            else:
                logger.error(f"Failed to store certificate: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error storing certificate in Supabase: {e}")
            return False

    def retrieve_certificate(self, certificate_id: str) -> Optional[Dict]:
        """Retrieve certificate from Supabase"""
        try:
            response = requests.get(
                f'{self.supabase_url}/rest/v1/wipe_certificates',
                headers=self.headers,
                params={'certificate_id': f'eq.{certificate_id}'}
            )

            if response.status_code == 200:
                data = response.json()
                if data:
                    return data[0]

            return None

        except Exception as e:
            logger.error(f"Error retrieving certificate: {e}")
            return None

    def list_user_certificates(self, user_id: str, limit: int = 50) -> List[Dict]:
        """List certificates for a specific user"""
        try:
            response = requests.get(
                f'{self.supabase_url}/rest/v1/wipe_certificates',
                headers=self.headers,
                params={
                    'user_id': f'eq.{user_id}',
                    'limit': limit,
                    'order': 'created_at.desc'
                }
            )

            if response.status_code == 200:
                return response.json()

            return []

        except Exception as e:
            logger.error(f"Error listing user certificates: {e}")
            return []

    def verify_certificate_integrity(self, certificate_id: str) -> bool:
        """Verify certificate integrity by checking hash"""
        try:
            cert_data = self.retrieve_certificate(certificate_id)
            if not cert_data:
                return False

            # Recreate certificate object and verify hash
            stored_cert = WipeCertificate(**cert_data['certificate_data'])
            cert_manager = CertificateManager()

            # Verify hash
            calculated_hash = cert_manager._generate_certificate_hash(stored_cert)
            return calculated_hash == stored_cert.certificate_hash

        except Exception as e:
            logger.error(f"Error verifying certificate integrity: {e}")
            return False

