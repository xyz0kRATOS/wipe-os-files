#!/usr/bin/env python3

"""
secure_wipe_core.py - Core Data Wiping Engine
NIST 800-88 Compliant Secure Data Wiping Tool
Compatible with Puppy Linux Bookworm
"""

import os
import sys
import json
import time
import subprocess
import hashlib
import hmac
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import secrets

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/secure-wipe/wipe_operations.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class WipeMethod(Enum):
    """NIST 800-88 Rev. 1 Compliant Wipe Methods"""
    NIST_CLEAR = "NIST_CLEAR"              # Single pass with zeros
    NIST_PURGE_OVERWRITE = "NIST_PURGE_OVERWRITE"  # Three pass overwrite
    NIST_PURGE_CRYPTO = "NIST_PURGE_CRYPTO"        # Cryptographic erase
    ATA_SECURE_ERASE = "ATA_SECURE_ERASE"          # Hardware secure erase
    ATA_ENHANCED_SECURE_ERASE = "ATA_ENHANCED_SECURE_ERASE"
    NVME_FORMAT = "NVME_FORMAT"                    # NVMe format with secure erase
    DOD_3PASS = "DOD_3PASS"                       # DoD 5220.22-M (legacy)

class WipeStatus(Enum):
    """Wipe Operation Status"""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    VERIFIED = "VERIFIED"

@dataclass
class DriveInfo:
    """Drive Information Structure"""
    device: str
    model: str
    serial: str
    size: str
    drive_type: str
    interface: str
    firmware: str
    security_status: str = "Unknown"
    hpa_status: str = "Not Present"
    dco_status: str = "Not Present"
    is_mounted: bool = False
    mount_points: List[str] = None
    partitions: List[Dict] = None
    wipe_capable: bool = True
    supported_methods: List[str] = None

    def __post_init__(self):
        if self.mount_points is None:
            self.mount_points = []
        if self.partitions is None:
            self.partitions = []
        if self.supported_methods is None:
            self.supported_methods = []

@dataclass
class WipeOperation:
    """Wipe Operation Tracking"""
    operation_id: str
    device: str
    method: WipeMethod
    status: WipeStatus
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
    passes_completed: int = 0
    total_passes: int = 1
    progress_percentage: float = 0.0
    verification_hash: Optional[str] = None
    error_message: Optional[str] = None
    compliance_level: str = "NIST-800-88-Rev1"

class SecureWipeEngine:
    """Core Secure Data Wiping Engine"""

    def __init__(self):
        self.operations: Dict[str, WipeOperation] = {}
        self.temp_dir = "/tmp/secure_wipe"
        os.makedirs(self.temp_dir, exist_ok=True)

    def detect_drive_capabilities(self, device: str) -> DriveInfo:
        """Detect drive capabilities and information"""
        logger.info(f"Detecting capabilities for {device}")

        try:
            # Get basic drive info
            drive_info = self._get_drive_basic_info(device)

            # Determine supported wipe methods
            supported_methods = self._get_supported_wipe_methods(drive_info)
            drive_info.supported_methods = supported_methods

            return drive_info

        except Exception as e:
            logger.error(f"Failed to detect drive capabilities: {e}")
            raise

    def _get_drive_basic_info(self, device: str) -> DriveInfo:
        """Get basic drive information"""
        try:
            # Get lsblk information
            result = subprocess.run([
                'lsblk', '-dpno', 'NAME,SIZE,MODEL,SERIAL,TYPE', device
            ], capture_output=True, text=True, check=True)

            lines = result.stdout.strip().split('\n')
            if not lines:
                raise ValueError(f"No information found for device {device}")

            parts = lines[0].split()
            size = parts[1] if len(parts) > 1 else "Unknown"
            model = " ".join(parts[2:-1]) if len(parts) > 3 else "Unknown"
            serial = parts[-1] if len(parts) > 2 else "Unknown"

            # Determine drive type and interface
            drive_type, interface = self._determine_drive_type(device)

            # Get firmware and security info
            firmware, security_status = self._get_drive_security_info(device, drive_type)

            # Check mount status
            is_mounted, mount_points = self._check_mount_status(device)

            # Get partition information
            partitions = self._get_partition_info(device)

            # Check for HPA/DCO
            hpa_status, dco_status = self._check_hpa_dco(device, drive_type)

            return DriveInfo(
                device=device,
                model=model,
                serial=serial,
                size=size,
                drive_type=drive_type,
                interface=interface,
                firmware=firmware,
                security_status=security_status,
                hpa_status=hpa_status,
                dco_status=dco_status,
                is_mounted=is_mounted,
                mount_points=mount_points,
                partitions=partitions
            )

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get drive info: {e}")
            raise

    def _determine_drive_type(self, device: str) -> Tuple[str, str]:
        """Determine drive type and interface"""
        if "nvme" in device:
            return "NVMe SSD", "NVMe"

        try:
            # Check rotational attribute
            rotational_path = f"/sys/block/{os.path.basename(device)}/queue/rotational"
            if os.path.exists(rotational_path):
                with open(rotational_path, 'r') as f:
                    rotational = f.read().strip()
                if rotational == "0":
                    return "SATA SSD", "SATA"
                else:
                    return "SATA HDD", "SATA"
        except:
            pass

        return "Unknown", "Unknown"

    def _get_drive_security_info(self, device: str, drive_type: str) -> Tuple[str, str]:
        """Get firmware and security information"""
        firmware = "Unknown"
        security_status = "Unknown"

        try:
            if "nvme" in drive_type.lower():
                # NVMe device
                result = subprocess.run(['nvme', 'id-ctrl', device],
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'fr ' in line.lower():
                            firmware = line.split()[-1]
                            break
            else:
                # SATA/ATA device
                result = subprocess.run(['hdparm', '-I', device],
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'firmware revision' in line.lower():
                            firmware = line.split(':')[-1].strip()
                        elif 'security:' in line.lower():
                            security_status = line.split(':')[-1].strip()

        except Exception as e:
            logger.warning(f"Could not get security info for {device}: {e}")

        return firmware, security_status

    def _check_mount_status(self, device: str) -> Tuple[bool, List[str]]:
        """Check if device is mounted"""
        try:
            result = subprocess.run(['lsblk', '-no', 'MOUNTPOINT', device],
                                  capture_output=True, text=True)
            mount_points = [mp for mp in result.stdout.strip().split('\n') if mp.strip()]
            return len(mount_points) > 0, mount_points
        except:

    def _unmount_device(self, device: str):
        """Unmount all partitions on the device"""
        try:
            result = subprocess.run(['lsblk', '-no', 'NAME', device],
                                  capture_output=True, text=True)
            device_names = result.stdout.strip().split('\n')

            for name in device_names[1:]:  # Skip parent device
                partition_path = f"/dev/{name.strip()}"
                try:
                    subprocess.run(['umount', partition_path],
                                 capture_output=True, check=False)
                    logger.info(f"Unmounted {partition_path}")
                except:
                    pass  # Ignore unmount errors
        except Exception as e:
            logger.warning(f"Could not unmount {device}: {e}")

    def _execute_ata_secure_erase(self, operation: WipeOperation, progress_callback) -> bool:
        """Execute ATA Secure Erase"""
        try:
            device = operation.device
            logger.info(f"Executing ATA Secure Erase on {device}")

            # Check if security is enabled
            result = subprocess.run(['hdparm', '-I', device],
                                  capture_output=True, text=True)
            if "not enabled" in result.stdout.lower():
                # Enable security with temporary password
                temp_password = "SecureWipe123"
                subprocess.run(['hdparm', '--user-master', 'u',
                              '--security-set-pass', temp_password, device],
                              check=True)
                logger.info("Enabled ATA security")

            if progress_callback:
                progress_callback(10, "Security enabled, starting erase...")

            # Execute secure erase
            subprocess.run(['hdparm', '--user-master', 'u',
                          '--security-erase', temp_password, device],
                          check=True, timeout=7200)  # 2 hour timeout

            if progress_callback:
                progress_callback(100, "ATA Secure Erase completed")

            operation.passes_completed = 1
            return True

        except subprocess.TimeoutExpired:
            logger.error(f"ATA Secure Erase timed out on {device}")
            return False
        except Exception as e:
            logger.error(f"ATA Secure Erase failed on {device}: {e}")
            return False

    def _execute_ata_enhanced_secure_erase(self, operation: WipeOperation, progress_callback) -> bool:
        """Execute ATA Enhanced Secure Erase"""
        try:
            device = operation.device
            logger.info(f"Executing ATA Enhanced Secure Erase on {device}")

            # Similar to regular secure erase but with enhanced option
            temp_password = "SecureWipe123"

            # Enable security
            subprocess.run(['hdparm', '--user-master', 'u',
                          '--security-set-pass', temp_password, device],
                          check=True)

            if progress_callback:
                progress_callback(10, "Security enabled, starting enhanced erase...")

            # Execute enhanced secure erase
            subprocess.run(['hdparm', '--user-master', 'u',
                          '--security-erase-enhanced', temp_password, device],
                          check=True, timeout=7200)

            if progress_callback:
                progress_callback(100, "ATA Enhanced Secure Erase completed")

            operation.passes_completed = 1
            return True

        except Exception as e:
            logger.error(f"ATA Enhanced Secure Erase failed on {device}: {e}")
            return False

    def _execute_nvme_format(self, operation: WipeOperation, progress_callback) -> bool:
        """Execute NVMe Secure Format"""
        try:
            device = operation.device
            logger.info(f"Executing NVMe Secure Format on {device}")

            if progress_callback:
                progress_callback(10, "Starting NVMe secure format...")

            # Execute NVMe format with secure erase
            subprocess.run(['nvme', 'format', device, '--ses=1'],
                          check=True, timeout=7200)

            if progress_callback:
                progress_callback(100, "NVMe Secure Format completed")

            operation.passes_completed = 1
            return True

        except Exception as e:
            logger.error(f"NVMe Secure Format failed on {device}: {e}")
            return False

    def _execute_nist_clear(self, operation: WipeOperation, progress_callback) -> bool:
        """Execute NIST Clear (single pass with zeros)"""
        try:
            device = operation.device
            logger.info(f"Executing NIST Clear on {device}")

            # Get device size in bytes
            size_bytes = self._get_device_size_bytes(device)

            if progress_callback:
                progress_callback(5, "Starting NIST Clear - single pass with zeros...")

            # Single pass with zeros using dd
            block_size = 1024 * 1024  # 1MB blocks
            total_blocks = size_bytes // block_size

            process = subprocess.Popen([
                'dd', f'if=/dev/zero', f'of={device}',
                f'bs={block_size}', f'count={total_blocks}',
                'conv=fdatasync', 'status=progress'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            # Monitor progress
            while process.poll() is None:
                if progress_callback:
                    # Estimate progress based on time (rough approximation)
                    elapsed = time.time() - operation.start_time.timestamp()
                    estimated_progress = min(90, (elapsed / 1800) * 100)  # 30 min estimate
                    progress_callback(estimated_progress, "Writing zeros to drive...")
                time.sleep(5)

            if process.returncode == 0:
                if progress_callback:
                    progress_callback(100, "NIST Clear completed")
                operation.passes_completed = 1
                return True
            else:
                logger.error(f"dd command failed with return code {process.returncode}")
                return False

        except Exception as e:
            logger.error(f"NIST Clear failed on {device}: {e}")
            return False

    def _execute_nist_purge_overwrite(self, operation: WipeOperation, progress_callback) -> bool:
        """Execute NIST Purge with 3-pass overwrite"""
        try:
            device = operation.device
            logger.info(f"Executing NIST Purge Overwrite on {device}")

            size_bytes = self._get_device_size_bytes(device)
            block_size = 1024 * 1024  # 1MB blocks
            total_blocks = size_bytes // block_size

            patterns = ['/dev/zero', '/dev/urandom', '/dev/zero']

            for pass_num, pattern in enumerate(patterns, 1):
                if progress_callback:
                    progress_callback(
                        (pass_num - 1) * 33,
                        f"NIST Purge Pass {pass_num}/3 - {pattern}..."
                    )

                process = subprocess.Popen([
                    'dd', f'if={pattern}', f'of={device}',
                    f'bs={block_size}', f'count={total_blocks}',
                    'conv=fdatasync'
                ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                process.wait()
                if process.returncode != 0:
                    logger.error(f"Pass {pass_num} failed")
                    return False

                operation.passes_completed = pass_num

                if progress_callback:
                    progress_callback(pass_num * 33, f"Pass {pass_num} completed")

            return True

        except Exception as e:
            logger.error(f"NIST Purge Overwrite failed on {device}: {e}")
            return False

    def _execute_dod_3pass(self, operation: WipeOperation, progress_callback) -> bool:
        """Execute DoD 5220.22-M 3-pass wipe"""
        try:
            device = operation.device
            logger.info(f"Executing DoD 3-Pass on {device}")

            size_bytes = self._get_device_size_bytes(device)

            # DoD patterns: 0x00, 0xFF, random
            passes = [
                ('zeros', 'if=/dev/zero'),
                ('ones', 'if=/dev/zero'),  # We'll use tr to convert to 0xFF
                ('random', 'if=/dev/urandom')
            ]

            for pass_num, (desc, input_source) in enumerate(passes, 1):
                if progress_callback:
                    progress_callback(
                        (pass_num - 1) * 33,
                        f"DoD Pass {pass_num}/3 - {desc}..."
                    )

                if desc == 'ones':
                    # Create ones pattern
                    cmd = f"tr '\\000' '\\377' < /dev/zero | dd of={device} bs=1M count={size_bytes//1048576} conv=fdatasync"
                    process = subprocess.Popen(cmd, shell=True)
                else:
                    process = subprocess.Popen([
                        'dd', input_source, f'of={device}',
                        'bs=1M', f'count={size_bytes//1048576}',
                        'conv=fdatasync'
                    ])

                process.wait()
                if process.returncode != 0:
                    return False

                operation.passes_completed = pass_num

                if progress_callback:
                    progress_callback(pass_num * 33, f"DoD Pass {pass_num} completed")

            return True

        except Exception as e:
            logger.error(f"DoD 3-Pass failed on {device}: {e}")
            return False

    def _execute_crypto_erase(self, operation: WipeOperation, progress_callback) -> bool:
        """Execute Cryptographic Erase (for SSDs with encryption)"""
        try:
            device = operation.device
            logger.info(f"Executing Cryptographic Erase on {device}")

            if progress_callback:
                progress_callback(10, "Starting cryptographic erase...")

            # For NVMe drives with encryption
            if 'nvme' in device:
                subprocess.run(['nvme', 'format', device, '--ses=2'],
                              check=True, timeout=300)
            else:
                # For SATA SSDs, try ATA security erase (crypto variant)
                temp_password = "CryptoWipe123"
                subprocess.run(['hdparm', '--user-master', 'u',
                              '--security-set-pass', temp_password, device],
                              check=True)
                subprocess.run(['hdparm', '--user-master', 'u',
                              '--security-erase', temp_password, device],
                              check=True, timeout=1800)

            if progress_callback:
                progress_callback(100, "Cryptographic erase completed")

            operation.passes_completed = 1
            return True

        except Exception as e:
            logger.error(f"Cryptographic erase failed on {device}: {e}")
            return False

    def _get_device_size_bytes(self, device: str) -> int:
        """Get device size in bytes"""
        try:
            result = subprocess.run(['blockdev', '--getsize64', device],
                                  capture_output=True, text=True, check=True)
            return int(result.stdout.strip())
        except:
            # Fallback method
            try:
                result = subprocess.run(['lsblk', '-bno', 'SIZE', device],
                                      capture_output=True, text=True, check=True)
                return int(result.stdout.strip().split('\n')[0])
            except:
                return 0

    def _verify_wipe(self, operation: WipeOperation):
        """Verify wipe completion by sampling random sectors"""
        try:
            device = operation.device
            logger.info(f"Verifying wipe for {device}")

            # Sample 1000 random 4KB blocks
            size_bytes = self._get_device_size_bytes(device)
            block_size = 4096
            total_blocks = size_bytes // block_size

            verification_data = []
            sample_count = min(1000, total_blocks // 1000)  # Sample 0.1% or 1000 blocks

            for _ in range(sample_count):
                random_block = secrets.randbelow(total_blocks)
                offset = random_block * block_size

                # Read block
                result = subprocess.run([
                    'dd', f'if={device}', 'bs=4096', f'skip={random_block}',
                    'count=1', 'status=none'
                ], capture_output=True)

                verification_data.extend(result.stdout)

            # Calculate hash of sampled data
            hash_obj = hashlib.sha256()
            hash_obj.update(bytes(verification_data))
            operation.verification_hash = hash_obj.hexdigest()

            # Check if data appears to be wiped (mostly zeros for most methods)
            non_zero_bytes = sum(1 for byte in verification_data if byte != 0)
            zero_percentage = (len(verification_data) - non_zero_bytes) / len(verification_data) * 100

            if zero_percentage > 95:  # 95% zeros indicates successful wipe
                operation.status = WipeStatus.VERIFIED
                logger.info(f"Wipe verification successful: {zero_percentage:.1f}% zeros")
            else:
                logger.warning(f"Wipe verification questionable: {zero_percentage:.1f}% zeros")

        except Exception as e:
            logger.error(f"Wipe verification failed: {e}")

    def get_operation_status(self, operation_id: str) -> Optional[WipeOperation]:
        """Get operation status"""
        return self.operations.get(operation_id)

    def get_operation_progress(self, operation_id: str) -> Tuple[float, str]:
        """Get operation progress"""
        if operation_id not in self.operations:
            return 0.0, "Operation not found"

        operation = self.operations[operation_id]
        return operation.progress_percentage, operation.status.value, []

    def _get_partition_info(self, device: str) -> List[Dict]:
        """Get partition information"""
        try:
            result = subprocess.run(['lsblk', '-no', 'NAME,SIZE,FSTYPE', device],
                                  capture_output=True, text=True)
            partitions = []
            lines = result.stdout.strip().split('\n')[1:]  # Skip parent device

            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 2:
                    partitions.append({
                        'name': parts[0],
                        'size': parts[1],
                        'filesystem': parts[2] if len(parts) > 2 else 'Unknown'
                    })
            return partitions
        except:
            return []

    def _check_hpa_dco(self, device: str, drive_type: str) -> Tuple[str, str]:
        """Check for HPA/DCO presence"""
        hpa_status = "Not Present"
        dco_status = "Not Present"

        if "sata" in drive_type.lower() or "ata" in drive_type.lower():
            try:
                result = subprocess.run(['hdparm', '-I', device],
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    output = result.stdout.lower()
                    if "hpa" in output:
                        hpa_status = "Present"
                    if "dco" in output:
                        dco_status = "Present"
            except:
                pass

        return hpa_status, dco_status

    def _get_supported_wipe_methods(self, drive_info: DriveInfo) -> List[str]:
        """Determine supported wipe methods based on drive type"""
        methods = []

        # All drives support basic overwrite methods
        methods.extend([WipeMethod.NIST_CLEAR.value, WipeMethod.DOD_3PASS.value])

        # Check for hardware secure erase capabilities
        if "ssd" in drive_info.drive_type.lower():
            methods.extend([
                WipeMethod.NIST_PURGE_CRYPTO.value,
                WipeMethod.NIST_PURGE_OVERWRITE.value
            ])
        else:
            methods.append(WipeMethod.NIST_PURGE_OVERWRITE.value)

        if "nvme" in drive_info.drive_type.lower():
            methods.append(WipeMethod.NVME_FORMAT.value)
        elif "sata" in drive_info.interface.lower() or "ata" in drive_info.interface.lower():
            if "not supported" not in drive_info.security_status.lower():
                methods.extend([
                    WipeMethod.ATA_SECURE_ERASE.value,
                    WipeMethod.ATA_ENHANCED_SECURE_ERASE.value
                ])

        return methods

    def create_wipe_operation(self, device: str, method: WipeMethod) -> str:
        """Create a new wipe operation"""
        operation_id = f"wipe_{int(time.time())}_{secrets.token_hex(4)}"

        # Determine number of passes based on method
        total_passes = 1
        if method == WipeMethod.DOD_3PASS:
            total_passes = 3
        elif method == WipeMethod.NIST_PURGE_OVERWRITE:
            total_passes = 3

        operation = WipeOperation(
            operation_id=operation_id,
            device=device,
            method=method,
            status=WipeStatus.PENDING,
            total_passes=total_passes
        )

        self.operations[operation_id] = operation
        logger.info(f"Created wipe operation {operation_id} for {device} using {method.value}")

        return operation_id

    def execute_wipe(self, operation_id: str, progress_callback=None) -> bool:
        """Execute wipe operation"""
        if operation_id not in self.operations:
            raise ValueError(f"Operation {operation_id} not found")

        operation = self.operations[operation_id]

        try:
            operation.status = WipeStatus.IN_PROGRESS
            operation.start_time = datetime.now(timezone.utc)
            logger.info(f"Starting wipe operation {operation_id}")

            # Unmount device if necessary
            self._unmount_device(operation.device)

            # Execute the appropriate wipe method
            success = False
            if operation.method == WipeMethod.ATA_SECURE_ERASE:
                success = self._execute_ata_secure_erase(operation, progress_callback)
            elif operation.method == WipeMethod.ATA_ENHANCED_SECURE_ERASE:
                success = self._execute_ata_enhanced_secure_erase(operation, progress_callback)
            elif operation.method == WipeMethod.NVME_FORMAT:
                success = self._execute_nvme_format(operation, progress_callback)
            elif operation.method == WipeMethod.NIST_CLEAR:
                success = self._execute_nist_clear(operation, progress_callback)
            elif operation.method == WipeMethod.NIST_PURGE_OVERWRITE:
                success = self._execute_nist_purge_overwrite(operation, progress_callback)
            elif operation.method == WipeMethod.DOD_3PASS:
                success = self._execute_dod_3pass(operation, progress_callback)
            elif operation.method == WipeMethod.NIST_PURGE_CRYPTO:
                success = self._execute_crypto_erase(operation, progress_callback)
            else:
                raise ValueError(f"Unsupported wipe method: {operation.method}")

            operation.end_time = datetime.now(timezone.utc)
            operation.duration = (operation.end_time - operation.start_time).total_seconds()

            if success:
                operation.status = WipeStatus.COMPLETED
                operation.progress_percentage = 100.0
                logger.info(f"Wipe operation {operation_id} completed successfully")

                # Perform verification
                self._verify_wipe(operation)
            else:
                operation.status = WipeStatus.FAILED
                logger.error(f"Wipe operation {operation_id} failed")

            return success

        except Exception as e:
            operation.status = WipeStatus.FAILED
            operation.error_message = str(e)
            operation.end_time = datetime.now(timezone.utc)
            logger.error(f"Wipe operation {operation_id} failed with error: {e}")
            return False

