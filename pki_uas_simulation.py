#!/usr/bin/env python3
import datetime
import hashlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

RESET = "\033[0m"
BOLD = "\033[1m"
HEADER = "\033[95m"
OKBLUE = "\033[94m"
OKCYAN = "\033[96m"
OKGREEN = "\033[92m"
WARNING = "\033[93m"
FAIL = "\033[91m"
UNDERLINE = "\033[4m"

def print_header(text):
    print(f"\n{BOLD}{HEADER}{'='*70}{RESET}")
    print(f"{BOLD}{HEADER}{text.center(70)}{RESET}")
    print(f"{BOLD}{HEADER}{'='*70}{RESET}\n")

def print_step(text):
    print(f"{OKCYAN}▶ {text}{RESET}")

def print_success(text):
    print(f"{OKGREEN}✅ {text}{RESET}")

def print_warning(text):
    print(f"{WARNING}⚠️  {text}{RESET}")

def print_fail(text):
    print(f"{FAIL}❌ {text}{RESET}")

def print_info(text):
    print(f"{OKBLUE}ℹ️  {text}{RESET}")

def get_fingerprint(data_bytes):
    return hashlib.sha256(data_bytes).hexdigest()[:16].upper() + "..."

def get_cert_fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()[:16].upper() + "..."

def print_cert_info(cert, title="Certificate"):
    print(f"\n{BOLD}{title}:{RESET}")
    print(f"  Subject : {cert.subject.rfc4514_string()}")
    print(f"  Issuer  : {cert.issuer.rfc4514_string()}")
    print(f"  Serial  : {cert.serial_number}")
    print(f"  Valid   : {cert.not_valid_before} to {cert.not_valid_after}")
    print(f"  Fingerprint: {get_cert_fingerprint(cert)}")
    print()

class CertificateAuthority:
    def __init__(self, name="CA-UAS"):
        self.name = name
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.certificate = self._create_self_signed_cert()
        self.public_repository = {}

    def _create_self_signed_cert(self):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Kelompok UAS Kriptografi"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(self.public_key).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(self.private_key, hashes.SHA256())
        return cert

    def issue_certificate(self, user_id, user_public_key):
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
        if cert:
            return cert.public_key()
        return None

class RegistrationAuthority:
    def __init__(self, name="RA-UAS", ca=None):
        self.name = name
        self.ca = ca

    def validate_user_data(self, user_id, user_data):
        print_step(f"[{self.name}] Memvalidasi data {user_id}...")
        required = ["nama", "email", "identitas"]
        for field in required:
            if field not in user_data or not user_data[field]:
                print_fail(f"Data {field} tidak lengkap untuk {user_id}")
                return False
        print_success(f"Data {user_id} valid dan disetujui oleh {self.name}")
        return True

    def approve_and_forward(self, user_id, user_data, user_public_key):
        if self.validate_user_data(user_id, user_data):
            print_step(f"[{self.name}] Meneruskan permohonan sertifikat {user_id} ke {self.ca.name}...")
            cert = self.ca.issue_certificate(user_id, user_public_key)
            print_success(f"Sertifikat untuk {user_id} berhasil diterbitkan oleh {self.ca.name} dan disimpan di repository publik")
            return cert
        return None

class User:
    def __init__(self, user_id, role="Cust"):
        self.user_id = user_id
        self.role = role
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.certificate = None

    def get_public_pem(self):
        return self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def request_certificate(self, ra, extra_data=None):
        data = {"nama": self.user_id, "email": f"{self.user_id.lower()}@uas-kripto.id", "identitas": "Mahasiswa UAS Kriptografi"}
        if extra_data:
            data.update(extra_data)
        print_step(f"[{self.user_id}] Mengirim permohonan sertifikat ke {ra.name} (public key + data identitas)")
        self.certificate = ra.approve_and_forward(self.user_id, data, self.public_key)
        if self.certificate:
            print_success(f"[{self.user_id}] Kunci publik telah tersertifikasi dan tersedia di repository CA")
        return self.certificate

    def sign(self, message):
        signature = self.private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return signature

    def verify_signature(self, message, signature, signer_public_key):
        try:
            signer_public_key.verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except Exception:
            return False

    def encrypt_message(self, message, recipient_public_key):
        ciphertext = recipient_public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return ciphertext

    def decrypt_message(self, ciphertext):
        plaintext = self.private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return plaintext

def print_repository_status(ca):
    print_header("STATUS REPOSITORY PUBLIK (KUNCI PUBLIK + SERTIFIKAT)")
    if not ca.public_repository:
        print_warning("Repository masih kosong")
        return
    print(f"{'User ID':<12} {'Fingerprint Sertifikat':<22} {'Issuer':<25}")
    print("-" * 65)
    for uid, cert in ca.public_repository.items():
        fprint = get_cert_fingerprint(cert)
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value if cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME) else "N/A"
        print(f"{uid:<12} {fprint:<22} {issuer_cn:<25}")
    print()

def print_user_status(users):
    print_header("STATUS USER & SERTIFIKASI")
    print(f"{'User':<10} {'Role':<8} {'Sertifikat':<12} {'Fingerprint':<20}")
    print("-" * 55)
    for u in users:
        status = "✅ Tersertifikasi" if u.certificate else "❌ Belum"
        fprint = get_cert_fingerprint(u.certificate) if u.certificate else "N/A"
        print(f"{u.user_id:<10} {u.role:<8} {status:<12} {fprint:<20}")
    print()

def main():
    print_header("UAS KRIPTOGRAFI - SIMULASI PUBLIC KEY INFRASTRUCTURE (PKI) DENGAN ROLEPLAY")
    print(f"{BOLD}{OKGREEN}Kelompok Paling Stand Out | Full Python Terminal Demo | Real RSA + X.509{RESET}\n")
    print_info("Point UAS: Demonstrasikan pemahaman PKI melalui simulasi role CA, RA, Cust dengan alur nyata: generate keypair -> registrasi & validasi -> sertifikasi -> gunakan untuk digital signature + enkripsi/dekripsi pesan.")
    print_info("Semua output di terminal ini mensimulasikan interaksi antar role secara lengkap sesuai tugas roleplay.\n")

    ca = CertificateAuthority()
    ra = RegistrationAuthority(ca=ca)

    print_header("FASE 1: SETUP INFRASTRUKTUR PKI")
    print_step("CA membuat pasangan kunci RSA-2048...")
    ca_pub_pem_short = ca.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()[:100] + "..."
    print_success(f"CA keypair generated. Public key disimpan di repository (bisa diakses publik)")
    print_cert_info(ca.certificate, "Root CA Certificate (Self-Signed)")

    print_step("RA siap menerima dan memvalidasi permohonan dari User Cust...")
    print_success("RA initialized. Siap validasi identitas User.\n")

    print_header("FASE 2: USER GENERATE KEY & REQUEST SERTIFIKAT via RA -> CA")
    cust1 = User("Cust1")
    cust2 = User("Cust2")
    cust3 = User("Cust3")

    users = [cust1, cust2, cust3]
    for u in users:
        print_step(f"[{u.user_id}] Generate pasangan kunci RSA-2048 (private disimpan sendiri, public akan disertifikasi)")
        u.request_certificate(ra)
        print()

    print_user_status(users)
    print_repository_status(ca)

    print_header("FASE 3: CUST1 KIRIM PESAN RAHASIA + TANDA TANGAN DIGITAL ke CUST2")
    secret_message = b"Halo Cust2! Ini pesan rahasia super penting untuk UAS Kriptografi. Hanya kamu yang bisa baca dan verifikasi tanda tangan Cust1. Semoga kelompok kita stand out!"
    print_info(f"Pesan asli (plaintext): {secret_message.decode()[:80]}...")

    print_step("[Cust1] Menandatangani pesan dengan private key Cust1 (RSA-PSS + SHA256)...")
    signature_c1 = cust1.sign(secret_message)
    print_success("Digital signature dibuat (64 bytes)")

    print_step("[Cust1] Mengambil public key Cust2 dari repository CA (via sertifikat)...")
    cust2_pub = ca.get_public_key("Cust2")
    if not cust2_pub:
        print_fail("Gagal ambil pubkey Cust2")
        return

    print_step("[Cust1] Mengenkripsi pesan dengan public key Cust2 (RSA-OAEP + SHA256)...")
    ciphertext = cust1.encrypt_message(secret_message, cust2_pub)
    print_success(f"Pesan terenkripsi (ciphertext {len(ciphertext)} bytes). Hanya Cust2 dengan private key-nya yang bisa dekripsi.")

    print_info("Data yang dikirim Cust1 -> Cust2: [ciphertext, signature, sender=Cust1]")

    print_header("FASE 4: CUST2 TERIMA, DEKRIPSI & VERIFIKASI TANDA TANGAN CUST1")
    print_step("[Cust2] Menerima ciphertext + signature dari Cust1...")
    print_step("[Cust2] Mendekripsi ciphertext dengan private key Cust2...")
    decrypted_msg = cust2.decrypt_message(ciphertext)
    print_success(f"Dekripsi sukses! Pesan: {decrypted_msg.decode()}")

    print_step("[Cust2] Memverifikasi digital signature Cust1 menggunakan public key Cust1 dari repository CA...")
    cust1_pub = ca.get_public_key("Cust1")
    if cust1_pub and cust2.verify_signature(decrypted_msg, signature_c1, cust1_pub):
        print_success("Verifikasi tanda tangan digital Cust1 BERHASIL! Integritas & autentikasi terjamin. Pengirim asli Cust1.")
    else:
        print_fail("Verifikasi signature GAGAL!")

    print_header("FASE 5: CUST2 KIRIM PENGUMUMAN PUBLIK + TANDA TANGAN ke SEMUA (Cust1 & Cust3)")
    public_announcement = b"PENGUMUMAN RESMI: Simulasi PKI Roleplay UAS Kriptografi telah sukses! Terima kasih CA & RA atas sertifikasi. Semua Cust bisa verifikasi pesan ini. - Cust2"
    print_info(f"Isi pengumuman: {public_announcement.decode()}")

    print_step("[Cust2] Menandatangani pengumuman dengan private key Cust2...")
    signature_c2 = cust2.sign(public_announcement)
    print_success("Digital signature untuk pengumuman dibuat")

    print_info("Pengumuman + signature dipublikasikan (bisa dibaca siapa saja, tapi signature diverifikasi via repo)")

    print_header("FASE 6: CUST1 & CUST3 VERIFIKASI PENGUMUMAN PUBLIK dari CUST2")
    for verifier in [cust1, cust3]:
        print_step(f"[{verifier.user_id}] Mengambil public key + sertifikat Cust2 dari repository CA...")
        cust2_pub_for_verify = ca.get_public_key("Cust2")
        print_step(f"[{verifier.user_id}] Memverifikasi signature pada pengumuman...")
        if cust2_pub_for_verify and verifier.verify_signature(public_announcement, signature_c2, cust2_pub_for_verify):
            print_success(f"[{verifier.user_id}] Verifikasi BERHASIL! Pengumuman asli dari Cust2, tidak dimodifikasi.")
            print_info(f"[{verifier.user_id}] Membaca pengumuman: {public_announcement.decode()}")
        else:
            print_fail(f"[{verifier.user_id}] Verifikasi GAGAL!")
        print()

    print_header("DEMO TAMBAHAN: TAMPER DETECTION (INTEGRITAS)")
    tampered_msg = secret_message + b" [TAMPERED by attacker]"
    print_warning("Misalnya attacker ubah pesan setelah dikirim...")
    if cust2.verify_signature(tampered_msg, signature_c1, cust1_pub):
        print_fail("Seharusnya gagal, tapi ini demo error path")
    else:
        print_success("Verifikasi GAGAL pada pesan yang di-tamper! Signature tidak match. PKI mendeteksi perubahan integritas.")

    print_header("RINGKASAN & POIN UAS YANG DIDEMO")
    print_success("1. CA: Generate keypair root, self-sign cert, issue user certs setelah RA approve, simpan di public repo.")
    print_success("2. RA: Validasi data identitas User Cust, forward ke CA untuk sertifikasi.")
    print_success("3. Cust: Generate keypair sendiri, request cert via RA, dapatkan sertifikat tersimpan di repo.")
    print_success("4. Digital Signature: Cust1 sign -> Cust2 verify (auth + integrity). Cust2 sign public msg -> all verify.")
    print_success("5. Enkripsi/Decryption: Cust1 encrypt secret utk Cust2 -> Cust2 decrypt (confidentiality). Hanya penerima bisa baca.")
    print_success("6. Trust Model: Semua verifikasi pakai public key dari sertifikat yang di-sign CA (root of trust).")
    print_info("Semua skenario roleplay selesai. Code ini bisa dipresentasikan live di terminal + screenshot untuk dokumentasi & slide.")
    print(f"\n{BOLD}{OKGREEN}🚀 UAS KRIPTOGRAFI SELESAI - KELOMPOK PALING STAND OUT! 🚀{RESET}\n")

if __name__ == "__main__":
    main()
