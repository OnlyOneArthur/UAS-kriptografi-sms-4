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
HEADER = "\033[95m"
OKBLUE = "\033[94m"
OKCYAN = "\033[96m"
OKGREEN = "\033[92m"
WARNING = "\033[93m"
FAIL = "\033[91m"

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_header(text):
    print(f"\n{BOLD}{HEADER}{'='*72}{RESET}")
    print(f"{BOLD}{HEADER}{text.center(72)}{RESET}")
    print(f"{BOLD}{HEADER}{'='*72}{RESET}\n")

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

class PKISimulator:
    def __init__(self):
        self.ca = None
        self.ra = None
        self.users = {}
        self.secret_message = b"Halo Cust2! Ini pesan rahasia super penting untuk UAS Kriptografi. Hanya kamu yang bisa baca dan verifikasi tanda tangan Cust1. Semoga kelompok kita stand out!"
        self.secret_cipher = None
        self.secret_sig = None
        self.public_announcement = b"PENGUMUMAN RESMI: Simulasi PKI Roleplay UAS Kriptografi telah sukses! Terima kasih CA & RA atas sertifikasi. Semua Cust bisa verifikasi pesan ini. - Cust2"
        self.public_sig = None

    def init_pki(self):
        clear_screen()
        print_header("FASE 1: INISIALISASI INFRASTRUKTUR PKI")
        self.ca = CertificateAuthority()
        self.ra = RegistrationAuthority(ca=self.ca)
        self.users = {}
        self.secret_cipher = None
        self.secret_sig = None
        self.public_sig = None
        print_step("CA membuat pasangan kunci RSA-2048...")
        print_success("CA keypair generated. Public key disimpan di repository (bisa diakses publik)")
        print_cert_info(self.ca.certificate, "Root CA Certificate (Self-Signed)")
        print_step("RA siap menerima dan memvalidasi permohonan dari User Cust...")
        print_success("RA initialized. Siap validasi identitas User.")
        print_success("PKI berhasil diinisialisasi!")

    def register_all_users(self):
        if not self.ca or not self.ra:
            print_fail("PKI belum diinisialisasi! Pilih menu 1 dulu.")
            return
        clear_screen()
        print_header("FASE 2: DAFTARKAN & SERTIFIKASI USER")
        for name in ["Cust1", "Cust2", "Cust3"]:
            if name not in self.users:
                u = User(name)
                u.request_certificate(self.ra)
                self.users[name] = u
                print()
        self.show_status()

    def show_status(self):
        print_header("STATUS USER & REPOSITORY")
        if not self.users:
            print_warning("Belum ada user yang tersertifikasi")
            return
        print(f"{'User':<10} {'Role':<8} {'Sertifikat':<15} {'Fingerprint':<20}")
        print("-" * 58)
        for uid, u in self.users.items():
            status = "✅ Tersertifikasi" if u.certificate else "❌ Belum"
            fprint = get_cert_fingerprint(u.certificate) if u.certificate else "N/A"
            print(f"{uid:<10} {u.role:<8} {status:<15} {fprint:<20}")
        print()
        if self.ca and self.ca.public_repository:
            print(f"{'User ID':<12} {'Fingerprint Sertifikat':<22} {'Issuer':<20}")
            print("-" * 58)
            for uid, cert in self.ca.public_repository.items():
                fprint = get_cert_fingerprint(cert)
                issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value if cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME) else "N/A"
                print(f"{uid:<12} {fprint:<22} {issuer_cn:<20}")
        print()

    def send_secret_cust1_to_cust2(self):
        if "Cust1" not in self.users or "Cust2" not in self.users:
            print_fail("Cust1 dan Cust2 belum tersertifikasi! Pilih menu 2 dulu.")
            return
        clear_screen()
        print_header("FASE 3: CUST1 KIRIM PESAN RAHASIA + TANDA TANGAN ke CUST2")
        print_info(f"Pesan asli: {self.secret_message.decode()[:70]}...")
        cust1 = self.users["Cust1"]
        cust2 = self.users["Cust2"]
        print_step("[Cust1] Menandatangani pesan dengan private key...")
        self.secret_sig = cust1.sign(self.secret_message)
        print_success("Digital signature dibuat (64 bytes)")
        print_step("[Cust1] Mengambil public key Cust2 dari repository CA...")
        cust2_pub = self.ca.get_public_key("Cust2")
        print_step("[Cust1] Mengenkripsi pesan dengan public key Cust2 (RSA-OAEP)...")
        self.secret_cipher = cust1.encrypt_message(self.secret_message, cust2_pub)
        print_success(f"Pesan terenkripsi ({len(self.secret_cipher)} bytes). Hanya Cust2 bisa dekripsi.")
        print_info("Data dikirim: [ciphertext + signature + sender=Cust1]")

    def cust2_process_secret(self):
        if not self.secret_cipher or not self.secret_sig:
            print_fail("Belum ada pesan rahasia dari Cust1! Pilih menu 4 dulu.")
            return
        clear_screen()
        print_header("FASE 4: CUST2 TERIMA, DEKRIPSI & VERIFIKASI TANDA TANGAN")
        cust2 = self.users["Cust2"]
        print_step("[Cust2] Mendekripsi ciphertext...")
        decrypted = cust2.decrypt_message(self.secret_cipher)
        print_success(f"Dekripsi sukses! Pesan: {decrypted.decode()}")
        print_step("[Cust2] Memverifikasi signature Cust1 dari repository...")
        cust1_pub = self.ca.get_public_key("Cust1")
        if cust1_pub and cust2.verify_signature(decrypted, self.secret_sig, cust1_pub):
            print_success("✅ Verifikasi BERHASIL! Integritas & autentikasi terjamin. Pengirim asli Cust1.")
        else:
            print_fail("Verifikasi GAGAL!")

    def send_public_announcement(self):
        if "Cust2" not in self.users:
            print_fail("Cust2 belum tersertifikasi!")
            return
        clear_screen()
        print_header("FASE 5: CUST2 KIRIM PENGUMUMAN PUBLIK + TANDA TANGAN")
        print_info(f"Isi pengumuman: {self.public_announcement.decode()}")
        cust2 = self.users["Cust2"]
        print_step("[Cust2] Menandatangani pengumuman...")
        self.public_sig = cust2.sign(self.public_announcement)
        print_success("Digital signature untuk pengumuman dibuat")
        print_info("Pengumuman + signature sekarang bisa diverifikasi siapa saja via repository CA")

    def verify_public_by_others(self):
        if not self.public_sig:
            print_fail("Belum ada pengumuman dari Cust2! Pilih menu 5 dulu.")
            return
        clear_screen()
        print_header("FASE 6: CUST1 & CUST3 VERIFIKASI PENGUMUMAN PUBLIK")
        for name in ["Cust1", "Cust3"]:
            if name not in self.users:
                continue
            verifier = self.users[name]
            print_step(f"[{name}] Mengambil public key Cust2 dari repository...")
            cust2_pub = self.ca.get_public_key("Cust2")
            print_step(f"[{name}] Memverifikasi signature...")
            if cust2_pub and verifier.verify_signature(self.public_announcement, self.public_sig, cust2_pub):
                print_success(f"✅ [{name}] Verifikasi BERHASIL! Pengumuman asli dari Cust2.")
                print_info(f"[{name}] Isi: {self.public_announcement.decode()}")
            else:
                print_fail(f"[{name}] Verifikasi GAGAL!")
            print()

    def tamper_demo(self):
        if not self.secret_sig or "Cust1" not in self.users:
            print_fail("Belum ada signature dari Cust1! Lakukan menu 4 dulu.")
            return
        clear_screen()
        print_header("DEMO TAMPER DETECTION (INTEGRITAS)")
        tampered = self.secret_message + b" [TAMPERED by attacker]"
        print_warning("Attacker mencoba ubah pesan setelah dikirim...")
        cust2 = self.users["Cust2"]
        cust1_pub = self.ca.get_public_key("Cust1")
        if cust2.verify_signature(tampered, self.secret_sig, cust1_pub):
            print_fail("Seharusnya gagal tapi ini demo")
        else:
            print_success("✅ Verifikasi GAGAL pada pesan yang di-tamper! PKI berhasil deteksi perubahan integritas.")

    def run_full_auto(self):
        clear_screen()
        print_header("JALANKAN FULL DEMO OTOMATIS")
        print_info("Menjalankan semua fase secara berurutan...")
        self.init_pki()
        input("Tekan Enter lanjut ke registrasi...")
        self.register_all_users()
        input("Tekan Enter lanjut kirim pesan rahasia...")
        self.send_secret_cust1_to_cust2()
        input("Tekan Enter lanjut proses di Cust2...")
        self.cust2_process_secret()
        input("Tekan Enter lanjut pengumuman publik...")
        self.send_public_announcement()
        input("Tekan Enter lanjut verifikasi publik...")
        self.verify_public_by_others()
        input("Tekan Enter lanjut demo tamper...")
        self.tamper_demo()
        print_header("FULL DEMO SELESAI")
        print_success("Semua skenario roleplay berhasil didemonstrasikan!")

    def menu_loop(self):
        while True:
            clear_screen()
            print_header("UAS KRIPTOGRAFI - PKI INTERACTIVE SIMULATOR (MENU)")
            print(f"{BOLD}{OKGREEN}Kelompok Paling Stand Out | Pilih sendiri apa yang mau didemo{RESET}\n")
            print("1. Inisialisasi PKI (CA + RA)")
            print("2. Daftarkan & Sertifikasi Semua Cust (Cust1,2,3)")
            print("3. Lihat Status User & Repository")
            print("4. Cust1 Kirim Pesan Rahasia + Tanda Tangan ke Cust2")
            print("5. Cust2 Kirim Pengumuman Publik + Tanda Tangan")
            print("6. Cust2 Buka & Verifikasi Pesan Rahasia dari Cust1")
            print("7. Cust1 & Cust3 Verifikasi Pengumuman Publik")
            print("8. Demo Tamper Detection (Integritas)")
            print("9. Jalankan Full Demo Otomatis (Semua Fase)")
            print("0. Keluar")
            print()
            choice = input("Pilih menu [0-9]: ").strip()
            if choice == "1":
                self.init_pki()
            elif choice == "2":
                self.register_all_users()
            elif choice == "3":
                clear_screen()
                self.show_status()
            elif choice == "4":
                self.send_secret_cust1_to_cust2()
            elif choice == "5":
                self.send_public_announcement()
            elif choice == "6":
                self.cust2_process_secret()
            elif choice == "7":
                self.verify_public_by_others()
            elif choice == "8":
                self.tamper_demo()
            elif choice == "9":
                self.run_full_auto()
            elif choice == "0":
                clear_screen()
                print_header("TERIMA KASIH")
                print_success("Semoga UAS Kriptografi lancar & kelompok paling stand out! 🔥")
                print_info("Jangan lupa screenshot tiap menu untuk dokumentasi & presentasi.")
                break
            else:
                print_fail("Pilihan tidak valid!")
            input("\nTekan Enter untuk kembali ke menu utama...")

def main():
    sim = PKISimulator()
    sim.menu_loop()

if __name__ == "__main__":
    main()
