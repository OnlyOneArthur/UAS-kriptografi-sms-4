#!/usr/bin/env python3
import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
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

def clear():
    os.system('clear' if os.name == 'posix' else 'cls')

def header(text):
    clear()
    with open("header_art.txt") as f:
        art_lines = f.read().splitlines()

    # Build the title box lines (left column)
    title_width = 40
    box_lines = [
        f"{BOLD}{CYAN}\u2554{'\u2550' * title_width}\u2557{RESET}",
        f"{BOLD}{WHITE}\u2551 {text.center(title_width - 2)} \u2551{RESET}",
        f"{BOLD}{CYAN}\u255a{'\u2550' * title_width}\u255d{RESET}",
    ]

    # Pad the shorter column so both have the same number of rows
    max_rows = max(len(art_lines), len(box_lines))
    # Center the title box vertically relative to the ASCII art
    box_top_pad = (max_rows - len(box_lines)) // 2
    padded_box = (
        [" " * (title_width + 2)] * box_top_pad
        + box_lines
        + [" " * (title_width + 2)] * (max_rows - len(box_lines) - box_top_pad)
    )
    padded_art = art_lines + [""] * (max_rows - len(art_lines))

    # Print side-by-side: title box on the left, ASCII art on the right
    gap = "   "
    for left, right in zip(padded_box, padded_art):
        print(f"{left}{gap}{BOLD}{MAGENTA}{right}{RESET}")
    print()

def section(text):
    print(f"\n{BOLD}{BLUE}\u250c\u2500 {text} {'\u2500'*(68-len(text))}\u2510{RESET}")

def step(text):
    print(f"{CYAN}\u2502 \u25b6 {text}{RESET}")

def ok(text):
    print(f"{GREEN}\u2502 \u2713 {text}{RESET}")

def warn(text):
    print(f"{YELLOW}\u2502 ! {text}{RESET}")

def err(text):
    print(f"{RED}\u2502 \u2717 {text}{RESET}")

def info(text):
    print(f"{BLUE}\u2502 i {text}{RESET}")

def close_box():
    print(f"{BOLD}{BLUE}\u2514{'\u2500'*74}\u2518{RESET}")

def get_fp(cert):
    return cert.fingerprint(hashes.SHA256()).hex()[:10].upper()

class CA:
    def __init__(self):
        self.priv = rsa.generate_private_key(65537, 2048)
        self.pub = self.priv.public_key()
        self.cert = self._create_root_cert()
        self.repo = {}

    def _create_root_cert(self):
        n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "UAS-PKI-CA")])
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        return (x509.CertificateBuilder()
                .subject_name(n).issuer_name(n).public_key(self.pub)
                .serial_number(x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
                .sign(self.priv, hashes.SHA256()))

    def issue_cert(self, uid, pubkey):
        n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, uid)])
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        cert = (x509.CertificateBuilder()
                .subject_name(n).issuer_name(self.cert.subject).public_key(pubkey)
                .serial_number(x509.random_serial_number())
                .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(x509.KeyUsage(True, True, True, False, False, False, False, False, False), True)
                .sign(self.priv, hashes.SHA256()))
        self.repo[uid] = cert
        return cert

class RA:
    def __init__(self, ca):
        self.ca = ca
        self.pending = {}
        self.approved = {}

    def receive_request(self, uid, nama, email):
        self.pending[uid] = {"nama": nama, "email": email, "pubkey": None}

    def approve(self, uid):
        if uid in self.pending:
            self.approved[uid] = self.pending.pop(uid)
            return True
        return False

class Cust:
    def __init__(self, uid):
        self.id = uid
        self.priv = rsa.generate_private_key(65537, 2048)
        self.pub = self.priv.public_key()
        self.cert = None

    def sign(self, message):
        return self.priv.sign(message, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())

    def verify(self, message, signature, pubkey):
        try:
            pubkey.verify(signature, message, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except:
            return False

    def encrypt(self, message, pubkey):
        return pubkey.encrypt(message, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), label=None))

    def decrypt(self, ciphertext):
        return self.priv.decrypt(ciphertext, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), label=None))

class Sim:
    def __init__(self):
        self.ca = None
        self.ra = None
        self.users = {}
        self.signed_messages = {}
        self.encrypted_messages = {}
        self.public_announcements = {}

    def start(self):
        header("UAS KRIPTOGRAFI \u2022 PKI SIMULATOR")
        print(f"{BOLD}{WHITE}   CA  \u2022  RA  \u2022  Cust1 / Cust2 / Cust3{RESET}")
        print(f"{CYAN}   Real Crypto \u2022 Role Play \u2022 Professional{RESET}\n")

    def init_pki(self):
        header("CA + RA INITIALIZATION")
        self.ca = CA()
        self.ra = RA(self.ca)
        ok("CA created (RSA-2048 + Root Certificate)")
        ok("RA connected to CA")
        close_box()

    def register_user(self):
        header("REGISTER NEW USER")
        uid = input("Username (e.g. yoga, agus, cust3): ").strip()
        if uid in self.users:
            warn(f"{uid} already exists")
            return
        nama = input("Full Name : ").strip() or uid
        email = input("Email     : ").strip() or f"{uid}@kripto.id"
        org = input("Organization: ").strip() or "UAS PKI Group"

        user = Cust(uid)
        self.users[uid] = user
        self.ra.receive_request(uid, nama, email)

        step(f"{uid} created key pair + sent request to RA")
        ok(f"Request for '{uid}' is now PENDING in RA")
        close_box()

    def ra_approve(self):
        header("RA \u2014 APPROVE REQUESTS")
        if not self.ra.pending:
            warn("No pending requests")
            return
        print("Pending Requests:")
        for i, uid in enumerate(self.ra.pending.keys(), 1):
            print(f"  {i}. {uid}")
        choice = input("Choose number to approve: ").strip()
        try:
            uid = list(self.ra.pending.keys())[int(choice)-1]
        except:
            err("Invalid choice")
            return

        if self.ra.approve(uid):
            ok(f"RA approved '{uid}' \u2192 ready for CA to issue certificate")
        close_box()

    def ca_issue(self):
        header("CA \u2014 ISSUE CERTIFICATES")
        if not self.ra.approved:
            warn("No approved requests")
            return
        print("Approved Requests:")
        for i, uid in enumerate(self.ra.approved.keys(), 1):
            print(f"  {i}. {uid}")
        choice = input("Choose number to issue certificate: ").strip()
        try:
            uid = list(self.ra.approved.keys())[int(choice)-1]
        except:
            err("Invalid choice")
            return

        user = self.users.get(uid)
        if user:
            cert = self.ca.issue_cert(uid, user.pub)
            user.cert = cert
            self.ra.approved.pop(uid)
            ok(f"Certificate issued for '{uid}'")
            print(f"  Fingerprint: {get_fp(cert)}")
        close_box()

    def show_status(self):
        header("SYSTEM STATUS")
        print(f"{BOLD}CA Status:{RESET} {'Ready' if self.ca else 'Not initialized'}")
        print(f"{BOLD}Registered Users:{RESET} {list(self.users.keys())}")
        print(f"{BOLD}Pending RA Approval:{RESET} {list(self.ra.pending.keys()) if self.ra else []}")
        print(f"{BOLD}Approved (waiting CA):{RESET} {list(self.ra.approved.keys()) if self.ra else []}")
        print(f"{BOLD}Issued Certificates:{RESET}")
        for uid, user in self.users.items():
            if user.cert:
                print(f"  \u2022 {uid:<8} \u2192 {get_fp(user.cert)}")
        close_box()

    def send_signed_secret(self):
        header("SEND SIGNED SECRET MESSAGE")
        print("Available users:", list(self.users.keys()))
        sender = input("Sender   : ").strip()
        receiver = input("Receiver : ").strip()
        if sender not in self.users or receiver not in self.users:
            err("User not found")
            return
        msg = input("Message  : ").encode()

        s = self.users[sender]
        sig = s.sign(msg)
        ct = s.encrypt(msg, self.users[receiver].pub)

        self.signed_messages[f"{sender}_to_{receiver}"] = {
            "sender": sender, "receiver": receiver,
            "ciphertext": ct, "signature": sig, "plaintext": msg
        }
        ok(f"Message signed by {sender} and encrypted for {receiver}")
        close_box()

    def decrypt_and_verify(self):
        header("DECRYPT & VERIFY SECRET MESSAGE")
        keys = list(self.signed_messages.keys())
        if not keys:
            warn("No messages")
            return
        for i, k in enumerate(keys, 1):
            print(f"  {i}. {k}")
        choice = input("Choose message: ").strip()
        try:
            key = keys[int(choice)-1]
        except:
            err("Invalid")
            return

        data = self.signed_messages[key]
        receiver = self.users[data["receiver"]]
        plaintext = receiver.decrypt(data["ciphertext"])
        valid = receiver.verify(plaintext, data["signature"], self.users[data["sender"]].pub)

        if valid:
            ok("Signature VALID + Decryption successful")
            print(f"  Message: {plaintext.decode()}")
        else:
            err("Signature INVALID")
        close_box()

    def publish_announcement(self):
        header("PUBLISH PUBLIC ANNOUNCEMENT")
        print("Available users:", list(self.users.keys()))
        sender = input("Who publishes? : ").strip()
        if sender not in self.users:
            err("User not found")
            return
        msg = input("Announcement: ").encode()
        sig = self.users[sender].sign(msg)
        self.public_announcements[sender] = {"message": msg, "signature": sig}
        ok(f"Public announcement published by {sender}")
        close_box()

    def verify_announcement(self):
        header("VERIFY PUBLIC ANNOUNCEMENT")
        if not self.public_announcements:
            warn("No announcements")
            return
        for sender, data in self.public_announcements.items():
            print(f"\nAnnouncement from: {sender}")
            for verifier_name, verifier in self.users.items():
                if verifier.cert:
                    valid = verifier.verify(data["message"], data["signature"], self.users[sender].pub)
                    status = "VALID \u2713" if valid else "INVALID \u2717"
                    print(f"  {verifier_name} verified: {status}")
        close_box()

    def tamper_test(self):
        header("TAMPER / NEGATIVE TEST")
        print("1. Tamper signed message")
        print("2. Tamper public announcement")
        ch = input("Choose: ").strip()
        if ch == "1":
            if not self.signed_messages:
                warn("No signed message yet")
                return
            key = list(self.signed_messages.keys())[0]
            data = self.signed_messages[key]
            receiver = self.users[data["receiver"]]
            bad_msg = b"HACKED MESSAGE!!!"
            valid = receiver.verify(bad_msg, data["signature"], self.users[data["sender"]].pub)
            if not valid:
                ok("Tamper detected! Signature INVALID on modified message")
            else:
                err("Unexpected: verification passed on tampered message")
        close_box()

    def reset_all(self):
        header("RESET ALL DATA")
        confirm = input("Are you sure you want to reset everything? (y/n): ").strip().lower()
        if confirm == "y":
            self.ca = None
            self.ra = None
            self.users = {}
            self.signed_messages = {}
            self.encrypted_messages = {}
            self.public_announcements = {}
            ok("All data has been reset. You can start fresh now.")
        else:
            warn("Reset cancelled")
        close_box()

    def menu(self):
        while True:
            self.start()
            print("  1. Init CA + RA")
            print("  2. Register New User (manual)")
            print("  3. RA \u2014 Approve Pending Requests")
            print("  4. CA \u2014 Issue Certificates")
            print("  5. Show Status / Repository")
            print("  6. Cust \u2014 Send Signed Secret Message")
            print("  7. Cust \u2014 Decrypt & Verify Secret")
            print("  8. Cust \u2014 Publish Public Announcement")
            print("  9. Cust \u2014 Verify Public Announcement")
            print("  t. Tamper / Negative Test")
            print("  r. Reset All Data")
            print("  0. Exit")
            print()
            ch = input("Choose: ").strip().lower()

            if ch == "1":
                self.init_pki()
            elif ch == "2":
                self.register_user()
            elif ch == "3":
                self.ra_approve()
            elif ch == "4":
                self.ca_issue()
            elif ch == "5":
                self.show_status()
            elif ch == "6":
                self.send_signed_secret()
            elif ch == "7":
                self.decrypt_and_verify()
            elif ch == "8":
                self.publish_announcement()
            elif ch == "9":
                self.verify_announcement()
            elif ch == "t":
                self.tamper_test()
            elif ch == "r":
                self.reset_all()
            elif ch == "0":
                header("THANKS FOR USING")
                print(f"{CYAN}All cryptography operations are real (RSA-2048 + X.509).{RESET}")
                close_box()
                break
            else:
                err("Invalid choice")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    Sim().menu()
