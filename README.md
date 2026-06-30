# UAS Kriptografi - Simulasi Public Key Infrastructure (PKI) dengan Roleplay

**Kelompok Paling Stand Out** | Full Terminal Demo | Real Cryptography (RSA + X.509)

## Point UAS Ini Sebenernya Ngapain? (Penjelasan Singkat)

UAS ini tugas **berkelompok dengan roleplay + dokumentasi lengkap** tentang **Public Key Infrastructure (PKI)**.

### Tujuan Utama:
- Paham konsep dasar PKI secara **praktis**, bukan cuma hafal teori.
- Demonstrasikan alur lengkap:
  1. **CA (Certificate Authority)**: Buat root keypair, self-sign certificate, terbitkan sertifikat user setelah approve.
  2. **RA (Registration Authority)**: Validasi identitas & data User Cust yang minta sertifikat.
  3. **Cust (User)**: Generate keypair sendiri → kirim public key + data ke RA → dapat sertifikat dari CA → simpan di public repository.
- Setelah sertifikat aktif, lakukan 4 skenario utama:
  - Cust1 kirim **pesan rahasia** ke Cust2 **+ tanda tangan digital** (hanya Cust2 bisa dekripsi + verifikasi siapa pengirimnya).
  - Cust2 kirim **pengumuman publik** yang bisa dibaca semua orang **+ tanda tangan digital** (Cust1 & Cust3 bisa verifikasi).
  - Cust2 terima & proses pesan rahasia Cust1.
  - Cust3 verifikasi pengumuman publik Cust2.
- Bonus: Tunjukkan **tamper detection** (integritas pesan).

### Kenapa Code Ini Stand Out?
- **Real crypto** pakai library `cryptography` (bukan simulasi bohongan/base64).
- **X.509 certificates** asli (self-signed CA root + CA-signed user certs).
- **Terminal UI keren** dengan warna, emoji, tabel status, fase terpisah (bisa live demo di presentasi).
- **Full roleplay** sesuai requirement: CA, RA, Cust1/2/3.
- **Enkripsi + Dekripsi + Digital Signature** semua berfungsi nyata.
- **No comments** di code Python (sesuai request kamu).
- Siap push ke GitHub, tinggal tambah dokumentasi slide Google Drive.

Presentasi: Jalankan script live di terminal → screenshot tiap fase → jelasin alur di slide + link repo ini.

## Cara Menjalankan di Arch Linux (atau distro lain)

```bash
# 1. Clone atau buat repo baru (contoh: UAS-kriptografi-sms-4)
git clone https://github.com/GianneAngely/UAS-kriptografi-sms-4.git
cd UAS-kriptografi-sms-4

# Atau buat baru:
mkdir UAS-kriptografi-pki && cd UAS-kriptografi-pki
git init

# 2. Install dependencies (Arch)
sudo pacman -S python python-pip
pip install --user cryptography

# Atau pakai venv (recommended)
python -m venv venv
source venv/bin/activate
pip install cryptography

# 3. Jalankan script (pastikan file pki_uas_simulation.py ada)
python pki_uas_simulation.py

# Atau buat executable
chmod +x pki_uas_simulation.py
./pki_uas_simulation.py
```

Output akan sangat colorful di terminal modern (Arch default bagus).

## Struktur File di Repo

- `pki_uas_simulation.py` → Full code Python (no comments, langsung jalan)
- `README.md` → Ini (dokumentasi + cara pakai)
- `requirements.txt` → Untuk reproducibility

## Cara Push ke GitHub (buat repo baru jika belum ada)

```bash
git add .
git commit -m "feat: full PKI roleplay simulation with real RSA+X509 for UAS Kriptografi"
git branch -M main
git remote add origin https://github.com/GianneAngely/UAS-kriptografi-sms-4.git
git push -u origin main
```

Lalu upload presentasi (slide + screenshot terminal) ke Google Drive, share link di jawaban UAS.

## Yang Ditunjukkan di Code (Sesuai Tugas Roleplay)

✅ CA buat keypair private sendiri, public di repo  
✅ RA validasi data Cust → approve → forward ke CA  
✅ Cust generate keypair → request cert via RA → dapat sertifikat  
✅ Cust1 & Cust2 (juga Cust3) tersertifikasi  
✅ Cust1 sign + encrypt secret message → hanya Cust2 decrypt + verify sig  
✅ Cust2 sign public announcement → Cust1 & Cust3 verify sig  
✅ Semua verifikasi pakai public key dari sertifikat di repo CA (trust chain)  
✅ Bonus: Tamper detection demo  

## Tips Presentasi & Dokumentasi

- Jalankan script full di laptop saat presentasi (tunjukkan live).
- Screenshot tiap header FASE.
- Di slide jelasin:
  - Teori singkat PKI (CA, RA, cert, digital sig, asymmetric encrypt)
  - Role masing-masing + mapping ke code
  - Kenapa pakai RSA-OAEP & PSS (modern best practice)
  - Manfaat nyata (confidentiality, integrity, authentication, non-repudiation)
- Tambahkan di slide: "Code ini 100% sesuai requirement UAS + extra real crypto biar stand out"

## Credits

Dibuat khusus untuk bantu kamu & kelompok dapat nilai maksimal di UAS Kriptografi.
Run it, screenshot, push ke GitHub, present with confidence! 🚀

Semoga UAS lancar dan kelompok paling stand out! Kalau butuh edit tambahan (misal tambah file output log, atau GUI sederhana), bilang aja.
