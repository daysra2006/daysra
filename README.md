# DAYSRA

Orkestrator pengujian keamanan otomatis berbasis niat (*intent-based*) yang deterministik, berpegang ketat pada batas cakupan otorisasi (*scope*), dan ramah pembelajaran pemula.

## Fitur Utama

- **Validasi Scope Ketat:** Engine Go mandiri sebagai satu-satunya penegak scope fail-closed.
- **Recon Subdomain Terkendali (M1):** Eksekusi tool `subfinder` aman tanpa shell, pemisahan data stdout dan log stderr, penghentian rapi SIGINT, deduplikasi host, dan normalisasi punycode IDN.
- **Probing HTTP Terintegrasi (M2):** Validasi host aktif via `httpx` (status code, title, teknologi, content length) dengan proteksi tanpa follow-redirect, pre & post-filter scope, dan streaming event `http`.
- **Penyimpanan SQLite Terstruktur:** Skema relasional `runs`, `hosts`, `host_obs`, dan `http_obs` dengan migrasi otomatis `PRAGMA user_version` (Python satu-satunya penulis).
- **Simple Mode di Terminal:** Ringkasan hasil recon seketika dengan tabel Rich:
  - Jumlah host unik dan host hidup
  - Sebaran sumber penemuan subdomain
  - Sebaran status code HTTP (2xx, 3xx, 4xx, 5xx)
  - 10 teknologi teratas
  - Daftar host dengan status menarik (3xx/4xx/5xx)
- **Laporan Markdown:** Hasilkan laporan GitHub-Flavored Markdown via Jinja2 (`daysra report`) mencakup ringkasan run, daftar subdomain, observasi host hidup, dan tanda peringatan jika run berstatus parsial.

## Instalasi & Pengembangan

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
make build
make test
make lint
make doctor
```

## Cara Pakai Recon & Probing

### 1. Inisialisasi Proyek (`daysra init`)
Jalankan inisialisasi untuk membuat file konfigurasi `~/.config/daysra/config.toml` (izin `0600`) dan template `scope.yaml` di direktori kerja:

```sh
daysra init
```

### 2. Atur Batas Scope (`scope.yaml`)
Pastikan file `scope.yaml` berisi otorisasi yang sah dan pola domain target yang diizinkan:

```yaml
authorization: "domain milik sendiri / lab / bug bounty <program>"
allow:
  - "example.com"
  - "*.example.com"
deny:
  - "admin.example.com"
max_rate: 50
timeout: 600
```

### 3. Jalankan Recon & Probe (`daysra recon`)
Lakukan enumerasi subdomain dan probing HTTP terhadap target dalam cakupan:

```sh
# Menjalankan enumerasi subdomain diikuti probing HTTP
daysra recon example.com --scope scope.yaml

# Melewati probing HTTP (hanya enumerasi subdomain)
daysra recon example.com --scope scope.yaml --no-probe
```

**Pilihan Opsi:**
- `--no-probe`: Melewati tahap probing httpx dan hanya menjalankan enumerasi subdomain.
- `--show-command`: Menampilkan sintaks perintah engine dan tool asli (`subfinder`, `httpx`) agar pengguna dapat mempelajari sintaks aslinya.
- `--raw`: Menampilkan aliran event JSONL mentah ke stdout tanpa format tabel Simple Mode.
- `--scope <path>`: Menentukan jalur file scope YAML khusus (default: `scope.yaml`).

Jika proses dihentikan menggunakan **Ctrl+C**, Daysra akan menghentikan proses anak secara rapi, menyimpan data sementara yang berhasil diamati dengan status `cancelled` (atau `partial` jika tahap probe terhenti), dan mengembalikan kode keluar yang sesuai.

### 4. Pindai Host Hidup (`daysra scan`)
Jalankan pemindaian Nuclei terhadap URL host hidup dari hasil recon terbaru yang tersimpan di SQLite:

```sh
# Pindai URL host hidup dari run recon terbaru untuk domain
daysra scan example.com --scope scope.yaml

# Pilih run sumber tertentu dan tampilkan command engine yang dijalankan
daysra scan example.com --scope scope.yaml --from-run <RUN_ID> --show-command

# Tambahkan tag template Nuclei (default-login tetap butuh konfirmasi eksplisit)
daysra scan example.com --scope scope.yaml --include-tags tech,exposure
```

Tanpa host hidup, Daysra menyuruh menjalankan `daysra recon example.com` lebih dulu dan tidak menjalankan engine. Jika `--include-tags` memuat `default-login`, Daysra meminta konfirmasi mengetik kata `default-login` pada terminal; tanpa konfirmasi tag itu dibuang. Flag `--accept-default-login` meneruskan tag tersebut tanpa bertanya.

### 5. Buat Laporan Markdown (`daysra report`)
Hasilkan laporan ringkas hasil recon dalam format Markdown:

```sh
# Laporan run terakhir yang dicetak ke terminal
daysra report

# Laporan untuk run ID tertentu
daysra report --run <RUN_ID>

# Menyimpan laporan ke file
daysra report -o laporan-recon.md
```
