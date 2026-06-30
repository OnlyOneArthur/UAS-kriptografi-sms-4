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

# Resolve path to header_art.txt relative to this script file,
# so it works regardless of the current working directory.
HEADER_ART_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "header_art.txt")

# Width reserved for the left title panel (chars)
LEFT_WIDTH = 44
# Width reserved for the right ASCII art panel (chars, trimmed to fit)
ART_WIDTH = 36

def clear():
    os.system('clear' if os.name == 'posix' else 'cls')

def _load_art_lines():
    """Load header_art.txt and scale it down to ART_WIDTH by trimming/truncating each line."""
    try:
        with open(HEADER_ART_PATH, encoding="utf-8") as f:
            raw = f.read().splitlines()
    except FileNotFoundError:
        return ["  [header_art.txt not found]"]

    # Strip trailing whitespace per line, then truncate to ART_WIDTH
    lines = [line.rstrip()[:ART_WIDTH] for line in raw]

    # Drop leading/trailing blank lines for a tighter look
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()

    return lines

def header(text):
    clear()

    art_lines = _load_art_lines()

    # ── Build the left panel lines ──────────────────────────────────────────
    # Row 0 : top border
    # Row 1 : title text
    # Row 2 : bottom border
    # Remaining rows are blank left-side padding so height matches art
    left_top    = f"{BOLD}{CYAN}\u2554{'\u2550' * (LEFT_WIDTH - 2)}\u2557{RESET}"
    left_title  = f"{BOLD}{WHITE}\u2551 {text.center(LEFT_WIDTH - 4)} \u2551{RESET}"
    left_bottom = f"{BOLD}{CYAN}\u255a{'\u2550' * (LEFT_WIDTH - 2)}\u255d{RESET}"
    left_blank  = f"{BOLD}{CYAN}\u2551{' ' * (LEFT_WIDTH - 2)}\u2551{RESET}"

    left_lines = [left_top, left_title, left_bottom]

    # Pad left panel height to match art height
    while len(left_lines) < len(art_lines):
        left_lines.append(" " * LEFT_WIDTH)

    # ── Zip left + right and print side-by-side ─────────────────────────────
    total = max(len(left_lines), len(art_lines))
    art_lines  += ["" ] * (total - len(art_lines))
    left_lines += [" " * LEFT_WIDTH] * (total - len(left_lines))

    print()  # top breathing room
    for left, art in zip(left_lines, art_lines):
        art_colored = f"{BOLD}{MAGENTA}{art:<{ART_WIDTH}}{RESET}"
        print(f"{left}  {art_colored}")
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
        print(f"{BOLD}{WHITE}   CA  \u2022  RA  \u2022  Cust1 / Cust2 / Cust3{RESET}")
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
        header("REGISTER USERS")
        for n in ["Cust1", "Cust2", "Cust3"]:
            if n not in self.c:
                u = Cust(n)
                u.ask_cert(self.ra)
                self.c[n] = u
        section("Status")
        for uid, u in self.c.items():
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
        if "Cust1" not in self.c or "Cust2" not in self.c:
            err("Register users first")
            return
        header("SECRET MESSAGE")
        msg = b"Hello Cust2, this is confidential from Cust1."
        c1 = self.c["Cust1"]
        section("Cust1")
        step("Signing with private key...")
        self.sg = c1.sign(msg)
        ok("Signature ready (RSASSA-PSS)")
        step("Encrypting for Cust2...")
        self.ct = c1.enc(msg, self.ca.pubkey("Cust2"))
        ok(f"Encrypted ({len(self.ct)} bytes)")
        close_box()

    def recv(self):
        if not self.ct:
            err("No secret sent yet")
            return
        header("DECRYPT & VERIFY")
        c2 = self.c["Cust2"]
        section("Cust2")
        step("Decrypting...")
        pt = c2.dec(self.ct)
        ok(f"Message: {pt.decode()}")
        step("Checking signature from Cust1...")
        if c2.verify(pt, self.sg, self.ca.pubkey("Cust1")):
            ok("Signature VALID \u2192 Authentic & intact")
        else:
            err("Signature INVALID")
        close_box()

    def pub(self):
        if "Cust2" not in self.c:
            err("Cust2 missing")
            return
        header("PUBLIC ANNOUNCEMENT")
        c2 = self.c["Cust2"]
        section("Cust2")
        step("Signing announcement...")
        self.psg = c2.sign(self.pmsg)
        ok("Announcement signed & published")
        info(self.pmsg.decode())
        close_box()

    def vpub(self):
        if not self.psg:
            err("No announcement yet")
            return
        header("VERIFY PUBLIC MSG")
        for n in ["Cust1", "Cust3"]:
            if n in self.c:
                c = self.c[n]
                step(f"{n} checking signature...")
                if c.verify(self.pmsg, self.psg, self.ca.pubkey("Cust2")):
                    ok(f"{n}: VALID")
                else:
                    err(f"{n}: INVALID")
        close_box()

    def tamper(self):
        if not self.sg:
            err("Send secret first")
            return
        header("TAMPER TEST")
        bad = b"Hacked message!!!"
        c2 = self.c["Cust2"]
        warn("Message was changed by attacker...")
        if c2.verify(bad, self.sg, self.ca.pubkey("Cust1")):
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
            print("  2. Register Cust1/2/3")
            print("  3. Show Status")
            print("  4. Cust1 send secret + sign")
            print("  5. Cust2 publish announcement")
            print("  6. Cust2 decrypt + verify")
            print("  7. Others verify announcement")
            print("  8. Tamper demo")
            print("  9. Full scenario")
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
                self.pub()
            elif ch == "6":
                self.recv()
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
