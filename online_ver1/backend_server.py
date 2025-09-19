#!/usr/bin/env python3

"""
backend_server.py - Flask Backend Server for Secure Data Wiping Tool
Handles API endpoints for drive detection, wiping operations, and certificate management
"""

import os
import json
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional
import logging
from flask import Flask, request, jsonify, send_file, abort
from flask_cors import CORS
import subprocess

# Import our custom modules
from secure_wipe_core import SecureWipeEngine, WipeMethod, DriveInfo
from certificate_manager import CertificateManager, SupabaseManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/secure-wipe/backend.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend communication

# Global instances
wipe_engine = SecureWipeEngine()
cert_manager = CertificateManager()
supabase_manager = None  # Will be initialized with config

# Configuration
CONFIG = {
    'SUPABASE_URL': os.getenv('SUPABASE_URL', ''),
    'SUPABASE_KEY': os.getenv('SUPABASE_KEY', ''),
    'MAX_CONCURRENT_WIPES': 1,  # Only allow one wipe at a time for safety
    'API_VERSION': '1.0'
}

# Thread-safe storage for active operations
active_operations = {}
operation_lock = threading.Lock()

def init_supabase():
    """Initialize Supabase connection"""
    global supabase_manager
    if CONFIG['SUPABASE_URL'] and CONFIG['SUPABASE_KEY']:
        supabase_manager = SupabaseManager(
            CONFIG['SUPABASE_URL'],
            CONFIG['SUPABASE_KEY']
        )
        logger.info("Supabase initialized successfully")
    else:
        logger.warning("Supabase credentials not provided")

@app.before_first_request
def startup():
    """Initialize services on startup"""
    init_supabase()
    logger.info("Backend server started")

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found', 'status': 'error'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error', 'status': 'error'}), 500

# API Routes

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': CONFIG['API_VERSION'],
        'timestamp': datetime.utcnow().isoformat(),
        'services': {
            'wipe_engine': 'ready',
            'certificate_manager': 'ready',
            'supabase': 'ready' if supabase_manager else 'not_configured'
        }
    })

@app.route('/api/drives/detect', methods=['GET'])
def detect_drives():
    """Detect all available drives"""
    try:
        logger.info("Starting drive detection")

        # Run drive detection script
        result = subprocess.run([
            'bash', '/opt/secure-wipe/bin/drive_detection.sh'
        ], capture_output=True, text=True, timeout=30)

        if result.returncode != 0:
            return jsonify({
                'status': 'error',
                'message': 'Drive detection failed',
                'error': result.stderr
            }), 500

        # Read detection results
        try:
            with open('/tmp/detected_drives.json', 'r') as f:
                detection_data = json.load(f)
        except FileNotFoundError:
            return jsonify({
                'status': 'error',
                'message': 'Detection results not found'
            }), 500

        logger.info(f"Detected {len(detection_data.get('detected_drives', []))} drives")

        return jsonify({
            'status': 'success',
            'data': detection_data,
            'timestamp': datetime.utcnow().isoformat()
        })

    except subprocess.TimeoutExpired:
        return jsonify({
            'status': 'error',
            'message': 'Drive detection timed out'
        }), 500
    except Exception as e:
        logger.error(f"Drive detection error: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/drives/<path:device>/info', methods=['GET'])
def get_drive_info(device):
    """Get detailed information for a specific drive"""
    try:
        # Sanitize device path
        if not device.startswith('/dev/'):
            device = f'/dev/{device}'

        drive_info = wipe_engine.detect_drive_capabilities(device)

        return jsonify({
            'status': 'success',
            'data': {
                'device': drive_info.device,
                'model': drive_info.model,
                'serial': drive_info.serial,
                'size': drive_info.size,
                'drive_type': drive_info.drive_type,
                'interface': drive_info.interface,
                'firmware': drive_info.firmware,
                'security_status': drive_info.security_status,
                'is_mounted': drive_info.is_mounted,
                'mount_points': drive_info.mount_points,
                'partitions': drive_info.partitions,
                'wipe_capable': drive_info.wipe_capable,
                'supported_methods': drive_info.supported_methods
            }
        })

    except Exception as e:
        logger.error(f"Error getting drive info for {device}: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/wipe/methods', methods=['GET'])
def get_wipe_methods():
    """Get available wipe methods with descriptions"""
    methods = {
        'NIST_CLEAR': {
            'name': 'NIST Clear',
            'description': 'Single pass overwrite with zeros (NIST 800-88 Clear)',
            'passes': 1,
            'time_estimate': 'Fast',
            'compliance': 'NIST 800-88 Rev. 1 - Clear',
            'suitable_for': ['Low security data', 'Quick sanitization']
        },
        'NIST_PURGE_OVERWRITE': {
            'name': 'NIST Purge - Overwrite',
            'description': 'Three-pass overwrite method (NIST 800-88 Purge)',
            'passes': 3,
            'time_estimate': 'Moderate',
            'compliance': 'NIST 800-88 Rev. 1 - Purge',
            'suitable_for': ['Moderate to high security', 'HDDs and SSDs']
        },
        'ATA_SECURE_ERASE': {
            'name': 'ATA Secure Erase',
            'description': 'Hardware-based secure erase (ATA command)',
            'passes': 1,
            'time_estimate': 'Fast',
            'compliance': 'NIST 800-88 Rev. 1 - Purge',
            'suitable_for': ['SATA drives with security feature', 'Hardware-level erase']
        },
        'ATA_ENHANCED_SECURE_ERASE': {
            'name': 'ATA Enhanced Secure Erase',
            'description': 'Enhanced hardware secure erase',
            'passes': 1,
            'time_estimate': 'Moderate',
            'compliance': 'NIST 800-88 Rev. 1 - Purge',
            'suitable_for': ['High security requirements', 'Enhanced security drives']
        },
        'NVME_FORMAT': {
            'name': 'NVMe Secure Format',
            'description': 'NVMe namespace format with secure erase',
            'passes': 1,
            'time_estimate': 'Fast',
            'compliance': 'NIST 800-88 Rev. 1 - Purge',
            'suitable_for': ['NVMe SSDs', 'Hardware-level erase']
        },
        'NIST_PURGE_CRYPTO': {
            'name': 'Cryptographic Erase',
            'description': 'Cryptographic key destruction',
            'passes': 1,
            'time_estimate': 'Very Fast',
            'compliance': 'NIST 800-88 Rev. 1 - Purge',
            'suitable_for': ['Self-encrypting drives', 'Instant erase']
        },
        'DOD_3PASS': {
            'name': 'DoD 5220.22-M',
            'description': 'Legacy DoD three-pass method',
            'passes': 3,
            'time_estimate': 'Slow',
            'compliance': 'DoD 5220.22-M (Legacy)',
            'suitable_for': ['Legacy compliance', 'Thorough overwrite']
        }
    }

    return jsonify({
        'status': 'success',
        'data': methods
    })

@app.route('/api/wipe/start', methods=['POST'])
def start_wipe():
    """Start a wipe operation"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                'status': 'error',
                'message': 'No data provided'
            }), 400

        device = data.get('device')
        method = data.get('method')
        user_id = data.get('user_id')  # Optional

        if not device or not method:
            return jsonify({
                'status': 'error',
                'message': 'Device and method are required'
            }), 400

        # Check if device path is valid
        if not device.startswith('/dev/'):
            device = f'/dev/{device}'

        if not os.path.exists(device):
            return jsonify({
                'status': 'error',
                'message': f'Device {device} not found'
            }), 404

        # Validate wipe method
        try:
            wipe_method = WipeMethod(method)
        except ValueError:
            return jsonify({
                'status': 'error',
                'message': f'Invalid wipe method: {method}'
            }), 400

        # Check for concurrent operations
        with operation_lock:
            if len(active_operations) >= CONFIG['MAX_CONCURRENT_WIPES']:
                return jsonify({
                    'status': 'error',
                    'message': 'Maximum concurrent wipe operations reached'
                }), 429

        # Create wipe operation
        operation_id = wipe_engine.create_wipe_operation(device, wipe_method)

        # Start wipe in background thread
        def run_wipe():
            with operation_lock:
                active_operations[operation_id] = {
                    'device': device,
                    'method': method,
                    'user_id': user_id,
                    'start_time': datetime.utcnow().isoformat()
                }

            try:
                # Execute wipe operation
                success = wipe_engine.execute_wipe(operation_id)

                if success:
                    logger.info(f"Wipe operation {operation_id} completed successfully")

                    # Generate certificate
                    operation = wipe_engine.get_operation_status(operation_id)
                    drive_info = wipe_engine.detect_drive_capabilities(device)

                    certificate = cert_manager.generate_wipe_certificate(
                        drive_info.__dict__,
                        operation.__dict__,
                        user_id
                    )

                    # Store certificate in Supabase if configured
                    if supabase_manager:
                        supabase_manager.store_certificate(certificate, user_id)

                    # Save certificate locally
                    cert_path = f"/opt/secure-wipe/certs/{certificate.certificate_id}.json"
                    cert_manager.export_certificate_json(certificate, cert_path)

                else:
                    logger.error(f"Wipe operation {operation_id} failed")

            except Exception as e:
                logger.error(f"Wipe operation {operation_id} failed with exception: {e}")

            finally:
                with operation_lock:
                    active_operations.pop(operation_id, None)

        # Start wipe thread
        wipe_thread = threading.Thread(target=run_wipe)
        wipe_thread.daemon = True
        wipe_thread.start()

        return jsonify({
            'status': 'success',
            'message': 'Wipe operation started',
            'operation_id': operation_id
        })

    except Exception as e:
        logger.error(f"Error starting wipe operation: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/wipe/status/<operation_id>', methods=['GET'])
def get_wipe_status(operation_id):
    """Get wipe operation status"""
    try:
        operation = wipe_engine.get_operation_status(operation_id)

        if not operation:
            return jsonify({
                'status': 'error',
                'message': 'Operation not found'
            }), 404

        progress, status_text = wipe_engine.get_operation_progress(operation_id)

        return jsonify({
            'status': 'success',
            'data': {
                'operation_id': operation.operation_id,
                'device': operation.device,
                'method': operation.method.value,
                'status': operation.status.value,
                'progress_percentage': operation.progress_percentage,
                'passes_completed': operation.passes_completed,
                'total_passes': operation.total_passes,
                'start_time': operation.start_time.isoformat() if operation.start_time else None,
                'end_time': operation.end_time.isoformat() if operation.end_time else None,
                'duration': operation.duration,
                'error_message': operation.error_message,
                'verification_hash': operation.verification_hash
            }
        })

    except Exception as e:
        logger.error(f"Error getting wipe status: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/wipe/operations', methods=['GET'])
def list_operations():
    """List all wipe operations"""
    try:
        operations = []

        for op_id, operation in wipe_engine.operations.items():
            operations.append({
                'operation_id': operation.operation_id,
                'device': operation.device,
                'method': operation.method.value,
                'status': operation.status.value,
                'start_time': operation.start_time.isoformat() if operation.start_time else None,
                'end_time': operation.end_time.isoformat() if operation.end_time else None,
                'duration': operation.duration
            })

        # Sort by start time (newest first)
        operations.sort(key=lambda x: x['start_time'] or '', reverse=True)

        return jsonify({
            'status': 'success',
            'data': {
                'operations': operations,
                'active_count': len(active_operations),
                'total_count': len(operations)
            }
        })

    except Exception as e:
        logger.error(f"Error listing operations: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/certificates/<certificate_id>', methods=['GET'])
def get_certificate(certificate_id):
    """Get certificate by ID"""
    try:
        # Try local storage first
        cert_path = f"/opt/secure-wipe/certs/{certificate_id}.json"

        if os.path.exists(cert_path):
            with open(cert_path, 'r') as f:
                cert_data = json.load(f)

            return jsonify({
                'status': 'success',
                'data': cert_data
            })

        # Try Supabase if configured
        if supabase_manager:
            cert_data = supabase_manager.retrieve_certificate(certificate_id)
            if cert_data:
                return jsonify({
                    'status': 'success',
                    'data': cert_data
                })

        return jsonify({
            'status': 'error',
            'message': 'Certificate not found'
        }), 404

    except Exception as e:
        logger.error(f"Error retrieving certificate: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/certificates/<certificate_id>/download', methods=['GET'])
def download_certificate(certificate_id):
    """Download certificate as file"""
    try:
        format_type = request.args.get('format', 'json').lower()

        # Get certificate data
        cert_path = f"/opt/secure-wipe/certs/{certificate_id}.json"

        if not os.path.exists(cert_path):
            abort(404)

        if format_type == 'json':
            return send_file(cert_path,
                           as_attachment=True,
                           download_name=f"{certificate_id}.json",
                           mimetype='application/json')
        elif format_type == 'pdf':
            # Generate PDF version
            with open(cert_path, 'r') as f:
                cert_data = json.load(f)

            # Convert to certificate object for PDF generation
            from certificate_manager import WipeCertificate
            certificate = WipeCertificate(**cert_data)

            pdf_path = f"/tmp/{certificate_id}.pdf"
            cert_manager.export_certificate_pdf(certificate, pdf_path)

            # Since we generate HTML instead of PDF (due to library requirements)
            html_path = pdf_path.replace('.pdf', '.html')
            if os.path.exists(html_path):
                return send_file(html_path,
                               as_attachment=True,
                               download_name=f"{certificate_id}.html",
                               mimetype='text/html')

        return jsonify({
            'status': 'error',
            'message': 'Invalid format or file not found'
        }), 400

    except Exception as e:
        logger.error(f"Error downloading certificate: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/certificates/<certificate_id>/verify', methods=['POST'])
def verify_certificate(certificate_id):
    """Verify certificate integrity and signature"""
    try:
        # Get certificate
        cert_path = f"/opt/secure-wipe/certs/{certificate_id}.json"

        if not os.path.exists(cert_path):
            return jsonify({
                'status': 'error',
                'message': 'Certificate not found'
            }), 404

        with open(cert_path, 'r') as f:
            cert_data = json.load(f)

        # Convert to certificate object
        from certificate_manager import WipeCertificate
        certificate = WipeCertificate(**cert_data)

        # Verify signature
        signature_valid = cert_manager.verify_certificate_signature(certificate)

        # Verify hash integrity
        calculated_hash = cert_manager._generate_certificate_hash(certificate)
        hash_valid = calculated_hash == certificate.certificate_hash

        # Check Supabase integrity if available
        supabase_valid = True
        if supabase_manager:
            supabase_valid = supabase_manager.verify_certificate_integrity(certificate_id)

        verification_result = {
            'certificate_id': certificate_id,
            'signature_valid': signature_valid,
            'hash_valid': hash_valid,
            'supabase_integrity': supabase_valid,
            'overall_valid': signature_valid and hash_valid and supabase_valid,
            'verification_timestamp': datetime.utcnow().isoformat()
        }

        return jsonify({
            'status': 'success',
            'data': verification_result
        })

    except Exception as e:
        logger.error(f"Error verifying certificate: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/certificates', methods=['GET'])
def list_certificates():
    """List certificates"""
    try:
        user_id = request.args.get('user_id')
        limit = int(request.args.get('limit', 50))

        certificates = []

        # Get from local storage
        cert_dir = "/opt/secure-wipe/certs"
        if os.path.exists(cert_dir):
            for filename in os.listdir(cert_dir):
                if filename.endswith('.json'):
                    cert_path = os.path.join(cert_dir, filename)
                    try:
                        with open(cert_path, 'r') as f:
                            cert_data = json.load(f)
                            certificates.append({
                                'certificate_id': cert_data.get('certificate_id'),
                                'device_model': cert_data.get('device_info', {}).get('model'),
                                'wipe_method': cert_data.get('wipe_operation', {}).get('method'),
                                'timestamp': cert_data.get('timestamp'),
                                'status': cert_data.get('wipe_operation', {}).get('status')
                            })
                    except:
                        continue

        # Get from Supabase if configured and user_id provided
        if supabase_manager and user_id:
            supabase_certs = supabase_manager.list_user_certificates(user_id, limit)
            for cert in supabase_certs:
                certificates.append({
                    'certificate_id': cert.get('certificate_id'),
                    'device_model': cert.get('device_model'),
                    'wipe_method': cert.get('wipe_method'),
                    'timestamp': cert.get('created_at'),
                    'status': cert.get('wipe_status')
                })

        # Remove duplicates and sort
        unique_certs = {cert['certificate_id']: cert for cert in certificates if cert['certificate_id']}.values()
        sorted_certs = sorted(unique_certs, key=lambda x: x['timestamp'] or '', reverse=True)

        return jsonify({
            'status': 'success',
            'data': {
                'certificates': list(sorted_certs)[:limit],
                'total_count': len(sorted_certs)
            }
        })

    except Exception as e:
        logger.error(f"Error listing certificates: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/system/info', methods=['GET'])
def get_system_info():
    """Get system information"""
    try:
        # Get system information
        info = {
            'hostname': os.uname().nodename,
            'system': f"{os.uname().sysname} {os.uname().release}",
            'architecture': os.uname().machine,
            'python_version': os.sys.version.split()[0],
            'tool_version': CONFIG['API_VERSION'],
            'uptime': None,
            'memory': None,
            'disk_space': None
        }

        # Get uptime
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
                info['uptime'] = f"{uptime_seconds / 3600:.1f} hours"
        except:
            pass

        # Get memory info
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
                for line in meminfo.split('\n'):
                    if 'MemTotal:' in line:
                        total_kb = int(line.split()[1])
                        info['memory'] = f"{total_kb / 1024 / 1024:.1f} GB"
                        break
        except:
            pass

        # Get disk space
        try:
            statvfs = os.statvfs('/opt/secure-wipe')
            free_bytes = statvfs.f_frsize * statvfs.f_bavail
            info['disk_space'] = f"{free_bytes / 1024 / 1024 / 1024:.1f} GB free"
        except:
            pass

        return jsonify({
            'status': 'success',
            'data': info
        })

    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get configuration information (non-sensitive)"""
    try:
        config_info = {
            'api_version': CONFIG['API_VERSION'],
            'max_concurrent_wipes': CONFIG['MAX_CONCURRENT_WIPES'],
            'supabase_configured': bool(CONFIG['SUPABASE_URL'] and CONFIG['SUPABASE_KEY']),
            'certificate_storage': 'local',
            'supported_formats': ['json', 'html'],
            'log_level': logging.getLogger().level
        }

        return jsonify({
            'status': 'success',
            'data': config_info
        })

    except Exception as e:
        logger.error(f"Error getting config: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# WebSocket-style endpoint for real-time progress (using Server-Sent Events)
@app.route('/api/wipe/<operation_id>/progress')
def wipe_progress_stream(operation_id):
    """Server-sent events for real-time wipe progress"""
    def generate():
        while True:
            operation = wipe_engine.get_operation_status(operation_id)
            if not operation:
                yield f"data: {json.dumps({'error': 'Operation not found'})}\n\n"
                break

            progress_data = {
                'operation_id': operation_id,
                'status': operation.status.value,
                'progress': operation.progress_percentage,
                'passes_completed': operation.passes_completed,
                'total_passes': operation.total_passes,
                'timestamp': datetime.utcnow().isoformat()
            }

            yield f"data: {json.dumps(progress_data)}\n\n"

            # Stop streaming when operation is complete
            if operation.status.value in ['COMPLETED', 'FAILED', 'VERIFIED']:
                break

            time.sleep(2)  # Update every 2 seconds

    return app.response_class(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        }
    )

if __name__ == '__main__':
    # Ensure directories exist
    os.makedirs('/opt/secure-wipe/logs', exist_ok=True)
    os.makedirs('/opt/secure-wipe/certs', exist_ok=True)
    os.makedirs('/var/log/secure-wipe', exist_ok=True)

    # Run the application
    app.run(
        host='0.0.0.0',
        port=8000,
        debug=False,  # Set to True for development
        threaded=True
    )

