import json
import os
import platform
import subprocess
import logging
import base64
from pathlib import Path
from datetime import datetime, timedelta
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Only import winreg when on Windows
try:
    import winreg
except ImportError:
    winreg = None


# Define custom exceptions
class LicenseError(Exception):
    """Base exception for license-related errors."""
    pass


class LicenseValidationError(LicenseError):
    """Raised when license validation fails."""
    pass


class LicenseEncryptionError(LicenseError):
    """Raised when encryption/decryption operations fail."""
    pass


@dataclass
class LicenseData:
    """Represents license data structure."""
    user: str
    expiry: str
    hardware_id: str


class TrialStatus(Enum):
    """Enumeration for trial status."""
    AVAILABLE = "available"
    ACTIVE = "active"
    EXPIRED = "expired"


class LicenseManager:
    """Manages software licensing and trial periods."""

    def __init__(self, app_name: str, encryption_key: bytes):
        """
        Initialize the license manager.

        Args:
            app_name: Name of the application
            encryption_key: Key used for encryption/decryption
        """
        self.app_name = app_name
        self.encryption_key = encryption_key
        self.trial_duration_days = 30
        self._setup_paths()
        self._configure_logging()

    def _encrypt_data(self, data: str) -> bytes:
        """
        Encrypt data using AES-GCM with a new random salt and nonce.

        Args:
            data: String data to encrypt

        Returns:
            Encrypted data as bytes
        """
        try:
            salt = os.urandom(16)
            key = self._derive_key(salt)
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
            return base64.b64encode(salt + nonce + ciphertext)
        except Exception as e:
            raise LicenseEncryptionError(f"Encryption failed: {e}")

    def _decrypt_data(self, encrypted_data: bytes) -> str:
        """
        Decrypt data that was encrypted by _encrypt_data.

        Args:
            encrypted_data: Encrypted data as bytes

        Returns:
            Decrypted string
        """
        try:
            decoded = base64.b64decode(encrypted_data)
            salt = decoded[:16]
            nonce = decoded[16:28]
            ciphertext = decoded[28:]
            key = self._derive_key(salt)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode()
        except Exception as e:
            raise LicenseEncryptionError(f"Decryption failed: {e}")

    def _derive_key(self, salt: bytes) -> bytes:
        """
        Derive a 256-bit key using PBKDF2 with the provided salt.

        Args:
            salt: Salt bytes for key derivation

        Returns:
            Derived key as bytes
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.encryption_key)

    def _setup_paths(self) -> None:
        """Setup paths for license and trial files based on OS."""
        base_path = self._get_base_path()
        self.license_file_path = base_path / "license.lic"
        self.last_valid_date_file = base_path / "last_valid_date.txt"
        self.trial_file_path = base_path / "trial_info.json"

        # Create directories if they don't exist
        base_path.mkdir(parents=True, exist_ok=True)

    def _get_base_path(self) -> Path:
        """Get the base path for storing license files based on OS."""
        system = platform.system()
        if system == "Windows":
            return Path(os.getenv('LOCALAPPDATA')) / self.app_name
        elif system == "Linux":
            return Path(f"/etc/{self.app_name}")
        elif system == "Darwin":
            return Path(f"/Library/Application Support/{self.app_name}")
        else:
            raise OSError(f"Unsupported operating system: {system}")

    def _configure_logging(self) -> None:
        """Configure logging with proper format and level."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(self._get_base_path() / "license.log"),
                logging.StreamHandler()
            ]
        )

    @staticmethod
    def generate_keys(private_key_path: Path, public_key_path: Path) -> None:
        """Generate RSA key pair with proper error handling."""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            # Save private key
            private_key_path.parent.mkdir(parents=True, exist_ok=True)
            private_key_path.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

            # Save public key
            public_key_path.parent.mkdir(parents=True, exist_ok=True)
            public_key_path.write_bytes(
                private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

            logging.info(f"Keys generated successfully: {private_key_path}, {public_key_path}")
        except Exception as e:
            raise LicenseError(f"Failed to generate keys: {e}")

    def create_license(self, private_key_path: Path, license_data: LicenseData) -> None:
        """Create and sign a license file with improved error handling."""
        try:
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_path.read_bytes(),
                password=None,
                backend=default_backend()
            )

            # Create and sign license
            license_dict = license_data.__dict__
            data_str = json.dumps(license_dict, sort_keys=True)
            signature = private_key.sign(
                data_str.encode(),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Create full license object
            license_full = {
                "data": license_dict,
                "signature": signature.hex()
            }

            # Encrypt and save
            encrypted_data = self._encrypt_data(json.dumps(license_full))
            self.license_file_path.write_bytes(encrypted_data)

            logging.info(f"License created successfully: {self.license_file_path}")
        except Exception as e:
            raise LicenseError(f"Failed to create license: {e}")

    def verify_license(self, public_key_path: Path) -> bool:
        """Verify license with comprehensive checks."""
        try:
            if not self.license_file_path.exists():
                raise LicenseValidationError("License file not found")

            # Load and decrypt license
            license_data = self._load_license_data(public_key_path)

            # Verify hardware ID
            if license_data["hardware_id"] != self.get_hardware_id():
                raise LicenseValidationError("Hardware ID mismatch")

            # Check expiration
            expiry_date = datetime.strptime(license_data["expiry"], "%Y-%m-%d")
            if datetime.now() > expiry_date:
                raise LicenseValidationError("License expired")

            # Check for clock tampering
            if self._is_clock_tampered(expiry_date):
                raise LicenseValidationError("Clock tampering detected")

            logging.info("License verification successful")
            return True

        except LicenseValidationError as e:
            logging.error(f"License validation failed: {e}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error during license verification: {e}")
            return False

    def _is_clock_tampered(self, expiry_date: datetime) -> bool:
        """Check for clock tampering by comparing with stored last valid date."""
        try:
            if not self.last_valid_date_file.exists():
                self.last_valid_date_file.write_text(datetime.now().strftime("%Y-%m-%d"))
                return False

            last_valid_date = datetime.strptime(
                self.last_valid_date_file.read_text().strip(),
                "%Y-%m-%d"
            )

            if datetime.now() < last_valid_date:
                return True  # Clock tampering detected

            self.last_valid_date_file.write_text(datetime.now().strftime("%Y-%m-%d"))
            return False
        except Exception as e:
            logging.error(f"Error checking clock tampering: {e}")
            return False

    def _load_license_data(self, public_key_path: Path) -> Dict[str, Any]:
        """Load and verify license data."""
        try:
            encrypted_license = self.license_file_path.read_bytes()
            decrypted_license = self._decrypt_data(encrypted_license)
            license_obj = json.loads(decrypted_license)

            # Verify signature
            public_key = serialization.load_pem_public_key(
                public_key_path.read_bytes(),
                backend=default_backend()
            )

            data_str = json.dumps(license_obj["data"], sort_keys=True)
            signature = bytes.fromhex(license_obj["signature"])

            try:
                public_key.verify(
                    signature,
                    data_str.encode(),
                    asym_padding.PSS(
                        mgf=asym_padding.MGF1(hashes.SHA256()),
                        salt_length=asym_padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except InvalidSignature:
                raise LicenseValidationError("Invalid signature")

            return license_obj["data"]

        except Exception as e:
            raise LicenseValidationError(f"Failed to load license data: {e}")

    def get_license_days_remaining(self, public_key_path: Path) -> int:
        """
        Get the number of days remaining until license expiration.

        Args:
            public_key_path: Path to the public key file

        Returns:
            Number of days remaining (0 if expired or invalid)
        """
        try:
            if not self.license_file_path.exists():
                return 0

            # Load and decrypt license
            license_data = self._load_license_data(public_key_path)

            # Calculate days remaining
            expiry_date = datetime.strptime(license_data["expiry"], "%Y-%m-%d")
            days_remaining = (expiry_date - datetime.now()).days

            return max(0, days_remaining)
        except Exception as e:
            logging.error(f"Error calculating license days remaining: {e}")
            return 0

    @staticmethod
    def get_hardware_id() -> str:
        """Get hardware ID with improved reliability."""
        system = platform.system()
        try:
            if system == "Windows":
                cpu_id = subprocess.check_output('wmic cpu get processorid', shell=True)
                disk_id = subprocess.check_output('wmic diskdrive get serialnumber', shell=True)
                return f"{cpu_id.decode().split()[1]}-{disk_id.decode().split()[1]}"
            elif system == "Linux":
                return Path("/etc/machine-id").read_text().strip()
            elif system == "Darwin":
                cmd = 'ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformSerialNumber'
                result = subprocess.check_output(cmd, shell=True)
                return result.decode().split('"')[-2]
            else:
                raise OSError(f"Unsupported operating system: {system}")
        except Exception as e:
            logging.error(f"Failed to get hardware ID: {e}")
            return "default_id"

    def get_trial_status(self) -> Tuple[TrialStatus, Optional[int]]:
        """Get current trial status and remaining days."""
        if not self._is_trial_started():
            return TrialStatus.AVAILABLE, self.trial_duration_days

        days_remaining = self.get_trial_days_remaining()
        if days_remaining > 0:
            return TrialStatus.ACTIVE, days_remaining
        return TrialStatus.EXPIRED, 0

    def _is_trial_started(self) -> bool:
        """Check if trial has been started."""
        if platform.system() == "Windows":
            return self._get_registry_trial_data()[0]
        return self._get_file_trial_data()[0]

    def get_trial_days_remaining(self) -> int:
        """Get number of trial days remaining."""
        if platform.system() == "Windows":
            _, start_date = self._get_registry_trial_data()
        else:
            _, start_date = self._get_file_trial_data()

        if not start_date:
            return self.trial_duration_days

        try:
            start = datetime.strptime(start_date, "%Y-%m-%d")
            days_used = (datetime.now() - start).days
            days_remaining = self.trial_duration_days - days_used
            return max(0, days_remaining)
        except Exception as e:
            logging.error(f"Error calculating trial days: {e}")
            return 0

    def _get_registry_trial_data(self) -> Tuple[bool, Optional[str]]:
        """Get trial data from Windows registry."""
        if not winreg:
            raise OSError("Windows registry access not available")

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"Software\\{self.app_name}") as key:
                trial_used = bool(winreg.QueryValueEx(key, "TrialUsed")[0])
                trial_start = winreg.QueryValueEx(key, "TrialStartDate")[0]
                return trial_used, trial_start
        except FileNotFoundError:
            return False, None

    def _get_file_trial_data(self) -> Tuple[bool, Optional[str]]:
        """Get trial data from file system."""
        if not self.trial_file_path.exists():
            return False, None

        try:
            data = json.loads(self.trial_file_path.read_text())
            return data.get("trial_used", False), data.get("trial_start_date")
        except Exception as e:
            logging.error(f"Failed to read trial data: {e}")
            return False, None
