# License Manager Documentation

## Overview
The License Manager script provides a secure system for software licensing, including license generation, validation, encryption, and a trial system. It ensures that only authorized users can use the application while offering a time-limited trial for evaluation.

## Features
- **License Generation**: Creates a digitally signed license for authorized users.
- **License Verification**: Checks license validity, expiration, and hardware ID.
- **Encryption & Security**: Uses AES-GCM for secure encryption and RSA for signing.
- **Trial System**: Provides a 30-day free trial with anti-clock tampering mechanisms.
- **Hardware Locking**: Binds the license to a specific device.

## Dependencies
This script requires the following Python libraries:
- `cryptography`
- `json`
- `os`
- `platform`
- `subprocess`
- `logging`
- `base64`
- `pathlib`
- `datetime`

## Usage

### 1. Initialize the License Manager
```python
from pathlib import Path
from datetime import datetime, timedelta
from license_manager import LicenseManager, LicenseData

manager = LicenseManager(
    app_name="MyAwesomeApp",
    encryption_key=b"your-secure-encryption-key-here"
)
```

### 2. Generate RSA Key Pair (First-Time Setup)
```python
private_key_path = Path("keys/private_key.pem")
public_key_path = Path("keys/public_key.pem")

LicenseManager.generate_keys(private_key_path, public_key_path)
```

### 3. Create a License
```python
license_data = LicenseData(
    user="john.doe@example.com",
    expiry=(datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d"),
    hardware_id=manager.get_hardware_id()
)
manager.create_license(private_key_path, license_data)
```

### 4. Verify the License
```python
is_valid = manager.verify_license(public_key_path)
if is_valid:
    print("✅ License is valid!")
else:
    print("❌ License is invalid or expired.")
```

### 5. Check Trial Status
```python
status, days_remaining = manager.get_trial_status()
if status == TrialStatus.AVAILABLE:
    print("🆕 Free trial available!")
elif status == TrialStatus.ACTIVE:
    print(f"⏳ Trial active with {days_remaining} days remaining")
elif status == TrialStatus.EXPIRED:
    print("❌ Trial has expired. Please purchase a license.")
```

## How It Works

### Encryption and Decryption
- Uses **AES-GCM** encryption with a derived key from PBKDF2-HMAC-SHA256.
- Generates a unique **salt** and **nonce** for each encryption operation.
- Base64 encodes encrypted data for storage.

### License Generation
- A license file is created containing:
  - User email
  - Expiry date
  - Hardware ID
- The license is digitally signed using **RSA**.
- The signed license is encrypted and stored.

### License Verification
- Decrypts the license and verifies the **RSA signature**.
- Compares stored **hardware ID** with the current machine.
- Checks if the **license is expired**.
- Detects **clock tampering** to prevent users from backdating their system clock.

### Trial Management
- The trial is stored in the **Windows Registry** (Windows) or a **JSON file** (Linux/macOS).
- Tracks the **start date** and ensures users do not reset trials by reinstalling.
- Prevents **clock tampering** by maintaining a last valid date check.

## Integration with Applications
To integrate with an application, use the following structure:

```python
class MyApplication:
    def __init__(self):
        self.license_manager = LicenseManager(
            app_name="MyAwesomeApp",
            encryption_key=b"your-secure-encryption-key-here"
        )

    def start(self):
        if not self._check_license():
            print("Please purchase a license or start a trial.")
            return False
        return self._run_application()

    def _check_license(self):
        if self.license_manager.verify_license(Path("keys/public_key.pem")):
            print("License verified!")
            return True
        status, days = self.license_manager.get_trial_status()
        return status == TrialStatus.ACTIVE

    def _run_application(self):
        print("Running application...")
        return True
```

## Conclusion
This License Manager ensures secure software licensing and trial management using encryption, digital signatures, and hardware locking. It prevents unauthorized use while allowing trial periods for evaluation.

