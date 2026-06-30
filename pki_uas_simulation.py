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
CYAN = "\033[36m"
BLUE = "\033[34m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"
WHITE = "\033[37m"

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def box_top():
    print(f"{BOLD}{CYAN}╔{'\u2550'*76}╗{RESET}")

def box_bottom():
    print(f"{BOLD}{CYAN}╚{'\u2550'*76}╝{RESET}")

def print_header(text):
    clear_screen()
    print(f"{BOLD}{MAGENTA}")
    print("   ██████\u2588\u2588 \u2588\u2588  \u2588\u2588\u2588\u2588")
    print("   \u2588\u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588 \u2588\u2588 \u2588\u2588")
    print("   \u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588\u2588\u2588\u2588 \u2588\u2588")
    print("   \u2588\u2588\u2588\u2588\u2588\u2588 \u2588\u2588 \u2588\u2588 \u2588\u2588")
    print("   \u2588\u2588     \u2588\u2588 \u2588\u2588  \u2588\u2588\u2588\u2588")
    print("   \u2588\u2588     \u2588\u2588 \u2588\u2588  \u2588\u2588  \u2588\u2588\u2588\u2588")
    print(f"{RESET}")
    print(f"{BOLD}{CYAN}╔{'\u2550'*76}╗{RESET}")
    print(f"{BOLD}{WHITE}║{text.center(76)}║{RESET}")
    print(f"{BOLD}{CYAN}╚{'\u2550'*76}╝{RESET}\n")

def print_section(text):
    print(f"\n{BOLD}{BLUE}┌─ {text} {'\u2500'*(70-len(text))}┐{RESET}")

def print_step(text):
    print(f"{CYAN}│  \u25b6 {text}{RESET}")

def print_success(text):
    print(f"{GREEN}│  \u2713 {text}{RESET}")

def print_warning(text):
    print(f"{YELLOW}│  ! {text}{RESET}")

def print_error(text):
    print(f"{RED}│  \u2717 {text}{RESET}")

def print_info(text):
    print(f"{BLUE}│  i {text}{RESET}")

def close_section():
    print(f"{BOLD}{BLUE}└{'\u2500'*76}┘{RESET}\n")

def get_fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()[:12].upper()

class CA:
    def __init__(self):
        self.name = "CA"
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.certificate = self._create_root_cert()
        self.repo = {}

    def _create_root_cert(self):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "UAS-CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kriptografi Lab"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        return x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(self.public_key).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(self.private_key, hashes.SHA256())

    def issue_cert(self, user_id, pubkey):
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, user_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cust"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(self.certificate.subject).public_key(pubkey).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365)).add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=True, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True).sign(self.private_key, hashes.SHA256())
        self.repo[user_id] = cert
        return cert

    def get_pubkey(self, user_id):
        cert = self.repo.get(user_id)
        return cert.public_key() if cert else None

    def get_cert(self, user_id):
        return self.repo.get(user_id)

class RA:
    def __init__(self, ca):
        self.name = "RA"
        self.ca = ca

    def validate(self, user_id, data):
        print_step(f"RA: Validating data for {user_id}...")
        if all(k in data and data[k] for k in ["nama", "email"]):
            print_success("RA: Data valid \u2192 forwarded to CA")
            return True
        print_error("RA: Data incomplete")
        return False

    def request_cert(self, user_id, data, pubkey):
        if self.validate(user_id, data):
            return self.ca.issue_cert(user_id, pubkey)
        return None

class Cust:
    def __init__(self, user_id):
        self.id = user_id
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.cert = None

    def request_cert(self, ra):
        data = {"nama": self.id, "email": f"{self.id}@kripto.id"}
        print_step(f"{self.id}: Sending request to RA...")
        self.cert = ra.request_cert(self.id, data, self.public_key)
        if self.cert:
            print_success(f"{self.id}: Certificate received from CA")
        return self.cert

    def sign(self, msg):
        return self.private_key.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    def verify(self, msg, sig, pubkey):
        try:
            pubkey.verify(sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except:
            return False

    def encrypt(self, msg, pubkey):
        return pubkey.encrypt(msg, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    def decrypt(self, ct):
        return self.private_key.decrypt(ct, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

class Simulator:
    def __init__(self):
        self.ca = None
        self.ra = None
        self.custs = {}
        self.secret_ct = None
        self.secret_sig = None
        self.pub_msg = b"PKI UAS simulation completed successfully. All signatures verified."
        self.pub_sig = None

    def init_pki(self):
        print_header("PKI INITIALIZATION")
        print_section("Setting up CA")
        self.ca = CA()
        print_success("CA: 2048-bit RSA keypair + self-signed root certificate created")
        print_section("Setting up RA")
        self.ra = RA(self.ca)
        print_success("RA ready. Public repository active.")
        box_bottom()

    def register_custs(self):
        if not self.ca:
            print_error("Run option 1 first!")
            return
        print_header("USER REGISTRATION")
        for name in ["Cust1", "Cust2", "Cust3"]:
            if name not in self.custs:
                c = Cust(name)
                c.request_cert(self.ra)
                self.custs[name] = c
        print_section("Current Status")
        for uid, c in self.custs.items():
            fp = get_fingerprint(c.cert) if c.cert else "N/A"
            print(f"  {uid:<6} | Certificate: {'\u2713 Issued' if c.cert else 'Pending'} | Fingerprint: {fp}")
        box_bottom()

    def show_status(self):
        print_header("REPOSITORY STATUS")
        if not self.custs:
            print_warning("No users registered yet.")
            return
        print(f"  {'User':<8} {'Status':<15} {'Fingerprint (SHA-256)'}")
        print("  " + "-"*60)
        for user_id, c in self.custs.items():
            status = "\u2713 Trusted" if c.cert else "Pending"
            fp = get_fingerprint(c.cert) if c.cert else "N/A"
            print(f"  {user_id:<8} {status:<15} {fp}")
        box_bottom()

    def send_secret(self):
        if "Cust1" not in self.custs or "Cust2" not in self.custs:
            print_error("Register users first (option 2)")
            return
        print_header("SECRET MESSAGE + SIGNATURE")
        msg = b"Confidential UAS message: Only Cust2 can read this."
        c1 = self.custs["Cust1"]
        c2 = self.custs["Cust2"]
        print_section("Cust1 Action")
        print_step("Signing message with private key (RSASSA-PSS)...")
        self.secret_sig = c1.sign(msg)
        print_success("Signature created")
        print_step("Encrypting with Cust2 public key (RSA-OAEP)...")
        self.secret_ct = c1.encrypt(msg, self.ca.get_pubkey("Cust2"))
        print_success(f"Encrypted ({len(self.secret_ct)} bytes). Ready to send.")
        box_bottom()

    def receive_secret(self):
        if not self.secret_ct:
            print_error("No secret message sent yet")
            return
        print_header("DECRYPT & VERIFY (Cust2)")
        c2 = self.custs["Cust2"]
        print_section("Cust2 Action")
        print_step("Decrypting with private key...")
        pt = c2.decrypt(self.secret_ct)
        print_success(f"Decrypted: {pt.decode()}")
        print_step("Verifying signature from Cust1...")
        if c2.verify(pt, self.secret_sig, self.ca.get_pubkey("Cust1")):
            print_success("Signature VALID \u2192 Message authentic & unmodified")
        else:
            print_error("Signature INVALID")
        box_bottom()

    def send_public(self):
        if "Cust2" not in self.custs:
            print_error("Cust2 not registered")
            return
        print_header("PUBLIC ANNOUNCEMENT + SIGNATURE")
        c2 = self.custs["Cust2"]
        print_section("Cust2 Action")
        print_step("Signing public announcement...")
        self.pub_sig = c2.sign(self.pub_msg)
        print_success("Signed announcement published to all")
        print_info(f"Message: {self.pub_msg.decode()}")
        box_bottom()

    def verify_public(self):
        if not self.pub_sig:
            print_error("No public announcement yet")
            return
        print_header("PUBLIC VERIFICATION")
        for name in ["Cust1", "Cust3"]:
            if name in self.custs:
                c = self.custs[name]
                print_step(f"{name} verifying signature from Cust2...")
                if c.verify(self.pub_msg, self.pub_sig, self.ca.get_pubkey("Cust2")):
                    print_success(f"{name}: Signature VALID")
                else:
                    print_error(f"{name}: Signature INVALID")
        box_bottom()

    def tamper_demo(self):
        if not self.secret_sig:
            print_error("Send secret message first")
            return
        print_header("TAMPER DETECTION")
        tampered = b"Tampered message!!!"
        c2 = self.custs["Cust2"]
        print_warning("Attacker modified the message after sending...")
        if c2.verify(tampered, self.secret_sig, self.ca.get_pubkey("Cust1")):
            print_error("Verification passed (unexpected)")
        else:
            print_success("Verification FAILED \u2192 Tampering detected successfully!")
        box_bottom()

    def full_run(self):
        print_header("FULL SCENARIO RUN")
        self.init_pki()
        input("Enter to continue...")
        self.register_custs()
        input("Enter to continue...")
        self.send_secret()
        input("Enter to continue...")
        self.receive_secret()
        input("Enter to continue...")
        self.send_public()
        input("Enter to continue...")
        self.verify_public()
        input("Enter to continue...")
        self.tamper_demo()
        print_header("ALL SCENARIOS COMPLETED")
        print_success("PKI role-play finished successfully.")
        box_bottom()

    def menu(self):
        while True:
            print_header("PKI ROLE-PLAY SIMULATOR")
            print(f"{BOLD}{WHITE}   CA  \u2022  RA  \u2022  Cust1 / Cust2 / Cust3{RESET}")
            print()
            print("  1. Initialize CA + RA")
            print("  2. Register Cust1, Cust2, Cust3")
            print("  3. Show Repository Status")
            print("  4. Cust1 \u2192 Send secret message + sign (to Cust2)")
            print("  5. Cust2 \u2192 Publish signed announcement")
            print("  6. Cust2 \u2192 Decrypt + verify secret message")
            print("  7. Cust1 & Cust3 \u2192 Verify public announcement")
            print("  8. Tamper Detection Demo")
            print("  9. Run Full Scenario (all steps)")
            print("  0. Exit")
            print()
            choice = input("Choose [0-9]: ").strip()
            if choice == "1":
                self.init_pki()
            elif choice == "2":
                self.register_custs()
            elif choice == "3":
                self.show_status()
            elif choice == "4":
                self.send_secret()
            elif choice == "5":
                self.send_public()
            elif choice == "6":
                self.receive_secret()
            elif choice == "7":
                self.verify_public()
            elif choice == "8":
                self.tamper_demo()
            elif choice == "9":
                self.full_run()
            elif choice == "0":
                print_header("THANKS FOR USING")
                print("""
   /\\_/\\  
  ( o.o )   ngopi dulu...
   > ^ < 
                """)
                print_success("All crypto is real (RSA-2048 + X.509). Good luck with your UAS!")
                break
            else:
                print_error("Invalid choice")
            input("\nPress Enter to return to menu...")

def main():
    sim = Simulator()
    sim.menu()

if __name__ == "__main__":
    main()
