#!/usr/bin/env python3
import datetime
import hashlib
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
BLUE = "\033[34m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
WHITE = "\033[37m"

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_header(text):
    print(f"\n{BOLD}{CYAN}{'='*78}{RESET}")
    print(f"{BOLD}{WHITE}{text.center(78)}{RESET}")
    print(f"{BOLD}{CYAN}{'='*78}{RESET}\n")

def print_section(text):
    print(f"\n{BOLD}{BLUE}{text}{RESET}")
    print(f"{DIM}{'-'*78}{RESET}")

def print_step(text):
    print(f"{CYAN}  \u2192 {text}{RESET}")

def print_success(text):
    print(f"{GREEN}  [OK] {text}{RESET}")

def print_warning(text):
    print(f"{YELLOW}  [WARN] {text}{RESET}")

def print_error(text):
    print(f"{RED}  [ERROR] {text}{RESET}")

def print_info(text):
    print(f"{BLUE}  [INFO] {text}{RESET}")

def get_cert_fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()[:16].upper()

def print_cert_details(cert, title="Certificate Information"):
    print(f"\n{BOLD}{title}{RESET}")
    print(f"  Subject     : {cert.subject.rfc4514_string()}")
    print(f"  Issuer      : {cert.issuer.rfc4514_string()}")
    print(f"  Serial      : {cert.serial_number}")
    print(f"  Not Before  : {cert.not_valid_before}")
    print(f"  Not After   : {cert.not_valid_after}")
    print(f"  Fingerprint : {get_cert_fingerprint(cert)} (SHA-256)")
    print()

class CertificateAuthority:
    def __init__(self, name="UAS-CA"):
        self.name = name
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.certificate = self._issue_self_signed_certificate()

    def _issue_self_signed_certificate(self):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UAS Kriptografi Laboratory"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(self.public_key).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(self.private_key, hashes.SHA256())
        return cert

    def issue_user_certificate(self, user_id, user_public_key):
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, user_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Custodian"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(self.certificate.subject).public_key(user_public_key).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365)).add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=True, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True).sign(self.private_key, hashes.SHA256())
        self.public_repository[user_id] = cert
        return cert

    def get_certificate(self, user_id):
        return self.public_repository.get(user_id)

    def get_public_key(self, user_id):
        cert = self.get_certificate(user_id)
        return cert.public_key() if cert else None

class RegistrationAuthority:
    def __init__(self, name="UAS-RA", ca=None):
        self.name = name
        self.ca = ca

    def validate_registration_request(self, user_id, user_data):
        print_step(f"Validating registration data for {user_id}...")
        required_fields = ["nama", "email", "identitas"]
        for field in required_fields:
            if field not in user_data or not user_data[field]:
                print_error(f"Missing required field: {field}")
                return False
        print_success(f"Registration data for {user_id} validated successfully")
        return True

    def process_certificate_request(self, user_id, user_data, user_public_key):
        if self.validate_registration_request(user_id, user_data):
            print_step(f"Forwarding approved request to Certificate Authority ({self.ca.name})")
            cert = self.ca.issue_user_certificate(user_id, user_public_key)
            print_success(f"X.509 certificate issued and stored in public repository")
            return cert
        return None

class User:
    def __init__(self, user_id, role="Custodian"):
        self.user_id = user_id
        self.role = role
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.certificate = None

    def request_certificate(self, ra):
        registration_data = {
            "nama": self.user_id,
            "email": f"{self.user_id.lower()}@uas-kriptografi.edu",
            "identitas": "Participant of Public Key Infrastructure Role-Play Exercise"
        }
        print_step(f"Submitting certificate request to Registration Authority ({ra.name})")
        self.certificate = ra.process_certificate_request(self.user_id, registration_data, self.public_key)
        if self.certificate:
            print_success(f"Certificate successfully obtained and stored in public repository")
        return self.certificate

    def create_digital_signature(self, message):
        signature = self.private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return signature

    def verify_digital_signature(self, message, signature, signer_public_key):
        try:
            signer_public_key.verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except Exception:
            return False

    def encrypt_with_recipient_key(self, message, recipient_public_key):
        ciphertext = recipient_public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return ciphertext

    def decrypt_with_private_key(self, ciphertext):
        plaintext = self.private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return plaintext

class PKISimulator:
    def __init__(self):
        self.ca = None
        self.ra = None
        self.users = {}
        self.secret_message = b"Confidential message for UAS Kriptografi examination: Only the intended recipient should be able to decrypt this content and verify the origin."
        self.encrypted_secret = None
        self.secret_signature = None
        self.public_announcement = b"Official announcement: All role-play scenarios for Public Key Infrastructure have been executed successfully. All digital signatures verified."
        self.announcement_signature = None

    def initialize_infrastructure(self):
        clear_screen()
        print_header("PUBLIC KEY INFRASTRUCTURE INITIALIZATION")
        print_section("Certificate Authority Setup")
        self.ca = CertificateAuthority()
        print_step("Generating 2048-bit RSA key pair for Certificate Authority")
        print_success("CA private key secured. Public key and self-signed root certificate published.")
        print_cert_details(self.ca.certificate, "Root CA Certificate (Self-Signed X.509 v3)")
        
        print_section("Registration Authority Setup")
        self.ra = RegistrationAuthority(ca=self.ca)
        print_success("Registration Authority ready to process certificate requests.")
        print_info("Public key repository initialized.")

    def perform_user_registration(self):
        if not self.ca or not self.ra:
            print_error("Infrastructure not initialized. Please select option 1 first.")
            return
        clear_screen()
        print_header("USER REGISTRATION AND CERTIFICATE ISSUANCE")
        for user_name in ["Custodian-01", "Custodian-02", "Custodian-03"]:
            if user_name not in self.users:
                user = User(user_name)
                print_section(f"Processing {user_name}")
                user.request_certificate(self.ra)
                self.users[user_name] = user
                print()
        self.display_repository_status()

    def display_repository_status(self):
        print_section("Public Key Repository Status")
        if not self.users:
            print_warning("No users have been registered yet.")
            return
        print(f"  {'User ID':<18} {'Certificate Status':<20} {'SHA-256 Fingerprint':<20}")
        print(f"  {'-'*18} {'-'*20} {'-'*20}")
        for user_id, user in self.users.items():
            status = "Issued & Trusted" if user.certificate else "Pending"
            fingerprint = get_cert_fingerprint(user.certificate) if user.certificate else "N/A"
            print(f"  {user_id:<18} {status:<20} {fingerprint:<20}")
        print()

    def execute_confidential_message_flow(self):
        if "Custodian-01" not in self.users or "Custodian-02" not in self.users:
            print_error("Required users not registered. Please complete option 2 first.")
            return
        clear_screen()
        print_header("CONFIDENTIAL MESSAGE TRANSMISSION WITH DIGITAL SIGNATURE")
        print_section("Message Preparation (Custodian-01)")
        print_info(f"Plaintext message: {self.secret_message.decode()[:80]}...")
        sender = self.users["Custodian-01"]
        recipient = self.users["Custodian-02"]
        
        print_step("Creating digital signature using RSASSA-PSS (SHA-256)")
        self.secret_signature = sender.create_digital_signature(self.secret_message)
        print_success("Digital signature generated (64 bytes)")
        
        print_step("Retrieving recipient public key from trusted repository")
        recipient_pubkey = self.ca.get_public_key("Custodian-02")
        
        print_step("Encrypting message using RSA-OAEP (SHA-256)")
        self.encrypted_secret = sender.encrypt_with_recipient_key(self.secret_message, recipient_pubkey)
        print_success(f"Message encrypted. Ciphertext length: {len(self.encrypted_secret)} bytes")
        print_info("Transmitted payload: ciphertext + digital signature + sender identity")

    def process_received_confidential_message(self):
        if not self.encrypted_secret or not self.secret_signature:
            print_error("No confidential message has been sent yet. Please complete option 4 first.")
            return
        clear_screen()
        print_header("MESSAGE DECRYPTION AND SIGNATURE VERIFICATION")
        print_section("Reception Process (Custodian-02)")
        recipient = self.users["Custodian-02"]
        
        print_step("Decrypting ciphertext using recipient private key (RSA-OAEP)")
        decrypted_message = recipient.decrypt_with_private_key(self.encrypted_secret)
        print_success(f"Decryption successful. Recovered plaintext: {decrypted_message.decode()}")
        
        print_step("Verifying digital signature using sender public key from repository")
        sender_pubkey = self.ca.get_public_key("Custodian-01")
        if sender_pubkey and recipient.verify_digital_signature(decrypted_message, self.secret_signature, sender_pubkey):
            print_success("Digital signature verification PASSED. Message integrity and authenticity confirmed.")
            print_info("Sender identity verified as Custodian-01 via trusted CA-issued certificate.")
        else:
            print_error("Digital signature verification FAILED.")

    def execute_public_announcement_flow(self):
        if "Custodian-02" not in self.users:
            print_error("Custodian-02 not registered.")
            return
        clear_screen()
        print_header("PUBLIC ANNOUNCEMENT WITH DIGITAL SIGNATURE")
        print_section("Announcement Creation (Custodian-02)")
        print_info(f"Announcement content: {self.public_announcement.decode()}")
        announcer = self.users["Custodian-02"]
        
        print_step("Generating digital signature over announcement (RSASSA-PSS + SHA-256)")
        self.announcement_signature = announcer.create_digital_signature(self.public_announcement)
        print_success("Signature created and attached to public announcement")
        print_info("Announcement is now publicly available. Any party can verify authenticity using the repository.")

    def verify_public_announcement(self):
        if not self.announcement_signature:
            print_error("No public announcement has been issued. Please complete option 5 first.")
            return
        clear_screen()
        print_header("PUBLIC ANNOUNCEMENT VERIFICATION BY THIRD PARTIES")
        print_section("Verification Process")
        for verifier_name in ["Custodian-01", "Custodian-03"]:
            if verifier_name not in self.users:
                continue
            verifier = self.users[verifier_name]
            print_step(f"{verifier_name} retrieving signer public key from trusted repository")
            signer_pubkey = self.ca.get_public_key("Custodian-02")
            print_step(f"{verifier_name} performing signature verification")
            if signer_pubkey and verifier.verify_digital_signature(self.public_announcement, self.announcement_signature, signer_pubkey):
                print_success(f"{verifier_name}: Signature verification PASSED. Announcement is authentic and unmodified.")
            else:
                print_error(f"{verifier_name}: Signature verification FAILED.")
            print()

    def demonstrate_integrity_protection(self):
        if not self.secret_signature or "Custodian-01" not in self.users:
            print_error("No signed message available for tamper demonstration.")
            return
        clear_screen()
        print_header("INTEGRITY PROTECTION DEMONSTRATION")
        print_section("Tamper Detection Scenario")
        tampered_message = self.secret_message + b" [MODIFIED BY UNAUTHORIZED PARTY]"
        print_warning("Simulating message modification after transmission...")
        recipient = self.users["Custodian-02"]
        sender_pubkey = self.ca.get_public_key("Custodian-01")
        if recipient.verify_digital_signature(tampered_message, self.secret_signature, sender_pubkey):
            print_error("Verification unexpectedly passed (should not happen).")
        else:
            print_success("Signature verification FAILED as expected. Unauthorized modification detected.")

    def execute_complete_scenario(self):
        clear_screen()
        print_header("COMPLETE ROLE-PLAY SCENARIO EXECUTION")
        print_info("Executing all phases sequentially for demonstration purposes.")
        self.initialize_infrastructure()
        input("\nPress Enter to continue with user registration...")
        self.perform_user_registration()
        input("\nPress Enter to continue with confidential message...")
        self.execute_confidential_message_flow()
        input("\nPress Enter to continue with message processing...")
        self.process_received_confidential_message()
        input("\nPress Enter to continue with public announcement...")
        self.send_public_announcement()
        input("\nPress Enter to continue with third-party verification...")
        self.verify_public_announcement()
        input("\nPress Enter to continue with integrity demonstration...")
        self.demonstrate_integrity_protection()
        print_header("SCENARIO EXECUTION COMPLETE")
        print_success("All Public Key Infrastructure role-play scenarios have been successfully demonstrated.")

    def run_interactive_menu(self):
        while True:
            clear_screen()
            print_header("UAS KRIPTOGRAFI - PUBLIC KEY INFRASTRUCTURE SIMULATION")
            print(f"{BOLD}{WHITE}Educational Role-Play Tool for Certificate Authority, Registration Authority, and Custodians{RESET}\n")
            print("  1. Initialize PKI Infrastructure (Certificate Authority + Registration Authority)")
            print("  2. Register Users and Issue X.509 Certificates")
            print("  3. Display Public Key Repository and Certificate Status")
            print("  4. Custodian-01: Send Confidential Message with Digital Signature")
            print("  5. Custodian-02: Issue Signed Public Announcement")
            print("  6. Custodian-02: Decrypt and Verify Received Confidential Message")
            print("  7. Third-Party Verification of Public Announcement")
            print("  8. Demonstrate Message Integrity Protection (Tamper Detection)")
            print("  9. Execute Complete Role-Play Scenario (All Steps)")
            print("  0. Exit Simulation")
            print()
            choice = input("Select option [0-9]: ").strip()
            if choice == "1":
                self.initialize_infrastructure()
            elif choice == "2":
                self.perform_user_registration()
            elif choice == "3":
                clear_screen()
                self.display_repository_status()
            elif choice == "4":
                self.execute_confidential_message_flow()
            elif choice == "5":
                self.execute_public_announcement_flow()
            elif choice == "6":
                self.process_received_confidential_message()
            elif choice == "7":
                self.verify_public_announcement()
            elif choice == "8":
                self.demonstrate_integrity_protection()
            elif choice == "9":
                self.execute_complete_scenario()
            elif choice == "0":
                clear_screen()
                print_header("SIMULATION TERMINATED")
                print_success("Thank you for using the Public Key Infrastructure Educational Simulator.")
                print_info("All cryptographic operations used real RSA-2048 with OAEP and PSS padding.")
                break
            else:
                print_error("Invalid selection. Please choose a number between 0 and 9.")
            input("\nPress Enter to return to main menu...")

def main():
    simulator = PKISimulator()
    simulator.run_interactive_menu()

if __name__ == "__main__":
    main()
