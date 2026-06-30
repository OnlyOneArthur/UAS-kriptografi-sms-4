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
- **Interactive Menu** → kamu bisa pilih sendiri langkah mana yang mau didemo saat presentasi!
- Siap push ke GitHub, tinggal tambah dokumentasi slide Google Drive.

Presentasi: Jalankan script → pilih menu interaktif → screenshot tiap langkah → jelasin alur di slide + link repo ini.

## Cara Menjalankan di Arch Linux (atau distro lain)

```bash
# 1. Clone repo
 git clone https://github.com/OnlyOneArthur/UAS-kriptografi-sms-4.git
 cd UAS-kriptografi-sms-4
 git checkout pki-roleplay-simulation

# 2. Install
pip install -r requirements.txt

# 3. Jalankan (interactive menu akan muncul)
python pki_uas_simulation.py
```

Output akan sangat colorful di terminal modern (Arch default bagus). Kamu bisa pilih menu 1-9 bebas.

## Struktur File di Repo

- `pki_uas_simulation.py` → Full code Python + Interactive Menu (no comments)
- `README.md` → Dokumentasi lengkap
- `requirements.txt` → Dependency

## Menu yang Tersedia

1. Inisialisasi PKI (CA + RA)
2. Daftarkan & Sertifikasi Semua Cust
3. Lihat Status User & Repository
4. Cust1 Kirim Pesan Rahasia + Signature ke Cust2
5. Cust2 Kirim Pengumuman Publik + Signature
6. Cust2 Buka & Verifikasi Pesan Rahasia
7. Cust1 & Cust3 Verifikasi Pengumuman Publik
8. Demo Tamper Detection
9. Full Demo Otomatis (jalan semua fase)
0. Keluar

## Tips Presentasi

- Jalankan script, tunjukkan menu interaktif
- Pilih menu satu per satu sesuai alur presentasi
- Screenshot setiap fase
- Tekankan bahwa code ini real RSA + X.509 + bisa milih sendiri (stand out!)

## Credits

Revisi interactive menu khusus buat kamu biar presentasi lebih fleksibel & keren.
Semoga UAS lancar dan nilai 100! 🚀
