from pathlib import Path
from datetime import datetime, timedelta
# Import LicenseGuard

def main():
    # Initialize the license manager with your app name and a secure encryption key
    manager = LicenseManager(
        app_name="MyAwesomeApp",
        encryption_key=b"your-secure-encryption-key-here"  # In production, use a secure key
    )

    # 1. First-time setup: Generate keys (only do this once, keep private key secure!)
    private_key_path = Path("keys/private_key.pem")
    public_key_path = Path("keys/public_key.pem")

    try:
        LicenseManager.generate_keys(private_key_path, public_key_path)
        print("✅ Keys generated successfully")
    except Exception as e:
        print(f"❌ Failed to generate keys: {e}")
        return

    # 2. Create a license for a user
    try:
        # Create license data
        license_data = LicenseData(
            user="john.doe@example.com",
            expiry=(datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d"),
            hardware_id=manager.get_hardware_id()
        )

        # Create the license
        manager.create_license(private_key_path, license_data)
        print("✅ License created successfully")
    except Exception as e:
        print(f"❌ Failed to create license: {e}")

    # 3. Verify the license
    if manager.verify_license(public_key_path):
        print("✅ License is valid!")
        # Proceed with application logic
        return

    # 4. If no valid license, check trial status
    trial_status, days_remaining = manager.get_trial_status()

    if trial_status == TrialStatus.AVAILABLE:
        print("🆕 Free trial available!")
        # Show trial registration screen

    elif trial_status == TrialStatus.ACTIVE:
        print(f"⏳ Trial active with {days_remaining} days remaining")
        # Proceed with application logic

    elif trial_status == TrialStatus.EXPIRED:
        print("❌ Trial period has expired")
        # Show purchase screen


# Example of integration with a simple application
class MyApplication:
    def __init__(self):
        self.license_manager = LicenseManager(
            app_name="MyAwesomeApp",
            encryption_key=b"your-secure-encryption-key-here"
        )

    def start(self):
        """Start the application with license checking."""
        if not self._check_license():
            print("Please purchase a license or start a trial to continue.")
            return False
        return self._run_application()

    def _check_license(self):
        """Check if the user can use the application."""
        # Try to verify full license first
        try:
            if self.license_manager.verify_license(Path("keys/public_key.pem")):
                print("Welcome back! License verified.")
                print(self.license_manager.get_license_days_remaining(Path("keys/public_key.pem")))
                return True
        except Exception as e:
            print(f"License verification failed: {e}")

        # If no valid license, check trial status
        status, days = self.license_manager.get_trial_status()

        if status == TrialStatus.AVAILABLE:
            user_choice = input("Would you like to start your free trial? (y/n): ")
            if user_choice.lower() == 'y':
                # Start trial logic here
                print("Trial started! Enjoy your 30-day trial.")
                return True

        elif status == TrialStatus.ACTIVE:
            print(f"Trial active - {days} days remaining")
            return True

        return False

    def _run_application(self):
        """Main application logic."""
        print("Application is running...")
        return True


# Usage example
if __name__ == "__main__":
    # Basic usage
    main()

    # Application integration
    print("\nStarting application...")
    app = MyApplication()
    app.start()
