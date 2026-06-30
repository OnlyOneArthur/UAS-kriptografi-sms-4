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
    print(f"{BOLD}{MAGENTA}")
    with open("header_art.txt") as f:
        print(f.read())
    print(f"{RESET}")
    print(f"{BOLD}{CYAN}╔{'\u2550'*74}╗{RESET}")
    print(f"{BOLD}{WHITE}║ {text.center(72)} ║{RESET}")
    print(f"{BOLD}{CYAN}╚{'\u2550'*74}╝{RESET}\n")

def section(text):
    print(f"\n{BOLD}{BLUE}┌─ {text} {'\u2500'*(68-len(text))}┐{RESET}")

def step(text):
    print(f"{CYAN}│ \u25b6 {text}{RESET}")

def ok(text):
    print(f"{GREEN}│ \u2713 {text}{RESET}")

def warn(text):
    print(f"{YELLOW}│ ! {text}{RESET}")

def err(text):
    print(f"{RED}│ \u2717 {text}{RESET}")

def info(text):
    print(f"{BLUE}│ i {text}{RESET}")

def close_box():
    print(f"{BOLD}{BLUE}└{'\u2500'*74}┘{RESET}")

def get_fp(cert):
    return cert.fingerprint(hashes.SHA256()).hex()[:10].upper()

class CA:
    def __init__(self):
        self.name = "CA"
        self.priv = rsa.generate_private_key(65537, 2048)
        self.pub = self.priv.public_key()
        self.cert = self._root()
        self.repo = {}

    def _root(self):
        n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "UAS-CA")])
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        return x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(self.pub).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(self.priv, hashes.SHA256())

    def issue(self, uid, pub):
        n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, uid)])
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        c = x509.CertificateBuilder().subject_name(n).issuer_name(self.cert.subject).public_key(pub).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365)).add_extension(x509.KeyUsage(True, True, True, False, False, False, False, False, False), True).sign(self.priv, hashes.SHA256())
        self.repo[uid] = c
        return c

    def pubkey(self, uid):
        c = self.repo.get(uid)
        return c.public_key() if c else None

class RA:
    def __init__(self, ca):
        self.ca = ca

    def ok(self, uid, data):
        step(f"RA checking {uid}...")
        if data.get("nama") and data.get("email"):
            ok("RA approved \u2192 sent to CA")
            return True
        err("RA: incomplete data")
        return False

    def ask(self, uid, data, pub):
        if self.ok(uid, data):
            return self.ca.issue(uid, pub)
        return None

class Cust:
    def __init__(self, uid):
        self.id = uid
        self.priv = rsa.generate_private_key(65537, 2048)
        self.pub = self.priv.public_key()
        self.cert = None

    def ask_cert(self, ra):
        step(f"{self.id} \u2192 sending request to RA")
        self.cert = ra.ask(self.id, {"nama": self.id, "email": f"{self.id}@kripto.id"}, self.pub)
        if self.cert:
            ok(f"{self.id} got certificate from CA")
        return self.cert

    def sign(self, m):
        return self.priv.sign(m, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())

    def verify(self, m, s, p):
        try:
            p.verify(s, m, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except:
            return False

    def enc(self, m, p):
        return p.encrypt(m, padding.OAEP(padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    def dec(self, c):
        return self.priv.decrypt(c, padding.OAEP(padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

class Sim:
    def __init__(self):
        self.ca = None
        self.ra = None
        self.c = {}
        self.ct = None
        self.sg = None
        self.pmsg = b"PKI roleplay finished. All signatures verified."
        self.psg = None

    def start(self):
        header("UAS KRIPTOGRAFI \u2022 PKI SIMULATOR")
        print(f"{BOLD}{WHITE}   CA  \u2022  RA  \u2022  registered users{RESET}")
        print(f"{CYAN}   Simple \u2022 Real crypto \u2022 Interactive{RESET}\n")

    def init(self):
        header("INITIALIZE PKI")
        section("CA Setup")
        self.ca = CA()
        ok("CA ready (2048-bit RSA + root cert)")
        section("RA Setup")
        self.ra = RA(self.ca)
        ok("RA connected to CA \u2022 Repository live")
        close_box()

    def reg(self):
        if not self.ca:
            err("Init first (option 1)")
            return
        header("REGISTER USER")
        uid = input("Enter username (e.g. yoga, agus, angel): ").strip()
        if not uid:
            err("Username cannot be empty")
            return
        if uid in self.c:
            warn(f"{uid} already registered")
            return
        print(f"\n{BOLD}{CYAN}Registering {uid}{RESET}")
        u = Cust(uid)
        u.ask_cert(self.ra)
        self.c[uid] = u
        section("Status")
        fp = get_fp(u.cert) if u.cert else "----"
        print(f"  {uid:<6}  {'\u2713 OK' if u.cert else '....'}   {fp}")
        close_box()

    def stat(self):
        header("REPOSITORY")
        if not self.c:
            warn("No users yet")
            return
        print(f"  User    Status     Fingerprint")
        print("  " + "-"*50)
        for user_id, c in self.c.items():
            print(f"  {user_id:<6}  {'\u2713 Trusted' if c.cert else 'Pending'}   {get_fp(c.cert) if c.cert else 'N/A'}")
        close_box()

    def secret(self):
        if not self.c:
            err("Register users first")
            return
        header("SECRET MESSAGE + SIGN")
        print("Available users:", list(self.c.keys()))
        sender = input("Sender   : ").strip()
        if sender not in self.c:
            err("Sender not found")
            return
        msg = input("Message  : ").encode()
        c1 = self.c[sender]
        section(sender)
        step("Signing with private key...")
        self.sg = c1.sign(msg)
        ok("Signature ready (RSASSA-PSS)")
        step("Encrypting for receiver...")
        # For simplicity, encrypt to first other user or ask
        receivers = [k for k in self.c if k != sender]
        if not receivers:
            err("No other user to send to")
            return
        recv_name = receivers[0] if len(receivers) == 1 else input(f"Receiver ({'/'.join(receivers)}): ").strip()
        if recv_name not in self.c:
            recv_name = receivers[0]
        self.ct = c1.enc(msg, self.ca.pubkey(recv_name))
        self.last_sender = sender
        self.last_receiver = recv_name
        ok(f"Encrypted message for {recv_name} ({len(self.ct)} bytes)")
        close_box()

    def recv(self):
        if not self.ct or not hasattr(self, 'last_receiver'):
            err("No secret message sent yet")
            return
        header("DECRYPT & VERIFY")
        receiver = self.last_receiver
        if receiver not in self.c:
            err("Receiver not found")
            return
        c2 = self.c[receiver]
        section(receiver)
        step("Decrypting...")
        pt = c2.dec(self.ct)
        ok(f"Message: {pt.decode()}")
        if hasattr(self, 'last_sender') and self.last_sender in self.c:
            step(f"Checking signature from {self.last_sender}...")
            if c2.verify(pt, self.sg, self.ca.pubkey(self.last_sender)):
                ok("Signature VALID \u2192 Authentic & intact")
            else:
                err("Signature INVALID")
        close_box()

    def pub(self):
        if not self.c:
            err("Register users first")
            return
        header("PUBLIC ANNOUNCEMENT")
        print("Available users:", list(self.c.keys()))
        sender = input("Who publishes? : ").strip()
        if sender not in self.c:
            err("User not found")
            return
        c2 = self.c[sender]
        section(sender)
        step("Signing announcement...")
        self.psg = c2.sign(self.pmsg)
        ok("Announcement signed & published")
        info(self.pmsg.decode())
        self.last_pub_sender = sender
        close_box()

    def vpub(self):
        if not self.psg or not hasattr(self, 'last_pub_sender'):
            err("No announcement yet")
            return
        header("VERIFY PUBLIC MSG")
        print("Available users:", list(self.c.keys()))
        verifier = input("Who verifies? : ").strip()
        if verifier not in self.c:
            err("User not found")
            return
        c = self.c[verifier]
        step(f"{verifier} checking signature from {self.last_pub_sender}...")
        if c.verify(self.pmsg, self.psg, self.ca.pubkey(self.last_pub_sender)):
            ok(f"{verifier}: VALID")
        else:
            err(f"{verifier}: INVALID")
        close_box()

    def tamper(self):
        if not self.sg or not hasattr(self, 'last_sender'):
            err("Send secret first")
            return
        header("TAMPER TEST")
        bad = b"Hacked message!!!"
        c2 = self.c.get(self.last_receiver)
        if not c2:
            err("Receiver not found")
            return
        warn("Message was changed by attacker...")
        if c2.verify(bad, self.sg, self.ca.pubkey(self.last_sender)):
            err("Verification passed (bad)")
        else:
            ok("Verification FAILED \u2192 Tamper detected!")
        close_box()

    def full(self):
        header("FULL RUN")
        self.init()
        input("Enter...")
        self.reg()
        input("Enter...")
        self.secret()
        input("Enter...")
        self.recv()
        input("Enter...")
        self.pub()
        input("Enter...")
        self.vpub()
        input("Enter...")
        self.tamper()
        header("DONE")
        ok("All scenarios completed successfully")
        close_box()

    def menu(self):
        while True:
            self.start()
            print("  1. Init CA + RA")
            print("  2. Register New User (one by one)")
            print("  3. Show Status")
            print("  4. Send Secret Message + Sign")
            print("  5. Decrypt & Verify Secret")
            print("  6. Publish Public Announcement")
            print("  7. Verify Public Announcement")
            print("  8. Tamper Detection Demo")
            print("  9. Full Auto Demo")
            print("  0. Exit")
            print()
            ch = input("Choose: ").strip()
            if ch == "1":
                self.init()
            elif ch == "2":
                self.reg()
            elif ch == "3":
                self.stat()
            elif ch == "4":
                self.secret()
            elif ch == "5":
                self.recv()
            elif ch == "6":
                self.pub()
            elif ch == "7":
                self.vpub()
            elif ch == "8":
                self.tamper()
            elif ch == "9":
                self.full()
            elif ch == "0":
                header("THANKS")
                print(f"{BOLD}{MAGENTA}")
                print("     /\\_/\\     ")
                print("    ( o.o )    ")
                print("     > ^ <     ")
                print(f"{RESET}")
                print(f"{CYAN}   ngopi dulu...{RESET}")
                print(f"{GREEN}All crypto is real (RSA-2048 + X.509).{RESET}")
                close_box()
                break
            else:
                err("Invalid")
            input("\nEnter to menu...")

if __name__ == "__main__":
    Sim().menu()
