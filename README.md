# DAYSRA

Orkestrator pengujian keamanan otomatis berbasis niat (*intent-based*) yang deterministik, berpegang ketat pada batas cakupan otorisasi (*scope*), dan ramah pembelajaran pemula.

## Fitur Utama

- **Validasi Scope Ketat:** Engine Go mandiri sebagai satu-satunya penegak scope fail-closed.
- **Recon Subdomain Terkendali (M1):** Eksekusi tool `subfinder` aman tanpa shell, pemisahan data stdout dan log stderr, penghentian rapi SIGINT, deduplikasi host, dan normalisasi punycode IDN.
- **Probing HTTP Terintegrasi (M2):** Validasi host aktif via `httpx` (status code, title, teknologi, content length) dengan proteksi tanpa follow-redirect, pre & post-filter scope, dan streaming event `http`.
- **Pemindaian Kerentanan Terkendali (M3):** Nuclei dijalankan pada URL host hidup dari hasil recon dengan profil tag aman, `-duc`/`-ni`, tanpa follow-redirect, deduplikasi temuan, serta evidence yang diredaksi dan dipotong sebelum disimpan.
- **Penyimpanan SQLite Terstruktur:** Skema relasional `runs`, `hosts`, `host_obs`, `http_obs`, `findings`, dan `finding_obs` dengan migrasi otomatis `PRAGMA user_version` (Python satu-satunya penulis).
- **Simple Mode di Terminal:** Ringkasan hasil recon seketika dengan tabel Rich:
  - Jumlah host unik dan host hidup
  - Sebaran sumber penemuan subdomain
  - Sebaran status code HTTP (2xx, 3xx, 4xx, 5xx)
  - 10 teknologi teratas
  - Daftar host dengan status menarik (3xx/4xx/5xx)
- **Laporan Markdown:** Hasilkan laporan GitHub-Flavored Markdown via Jinja2 (`daysra report`) mencakup ringkasan run, daftar subdomain, observasi host hidup, tanda peringatan jika run berstatus parsial/cancelled, serta seksi temuan untuk run scan (jumlah per severity, penjelasan knowledge base, `matched_at`, dan CVE tanpa evidence).

## Instalasi & Pengembangan

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
make build
make test
make lint
make doctor
```

`make doctor` (atau `daysra doctor`) memeriksa binary engine Go serta versi `subfinder`, `httpx`, dan `nuclei` yang terpasang, lalu memastikan izin `config.toml` aman. Jalankan ini setelah instalasi dan setiap kali tool diperbarui.

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
- `--show-command`: Menampilkan sintaks perintah engine dan tool asli (`subfinder`, `httpx`, `nuclei`) agar pengguna dapat mempelajari sintaks aslinya. Argumen tool diambil dari subcommand `daysra-engine show-command`, sehingga `-timeout`, `-rl`, tag, dan severity selalu sama dengan yang benar-benar dieksekusi.
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

Tanpa host hidup, Daysra menyuruh menjalankan `daysra recon example.com` lebih dulu dan tidak menjalankan engine. Run scan disimpan dengan target domain yang sudah lolos preflight scope, dan `--from-run` ditolak bila target run sumber tidak sama dengan domain yang diminta. Jika `--include-tags` memuat `default-login`, Daysra meminta konfirmasi mengetik kata `default-login` pada terminal; tanpa konfirmasi tag itu dibuang. Flag `--accept-default-login` meneruskan tag tersebut tanpa bertanya.

#### Menambah entri knowledge base

Simple Mode mengambil penjelasan temuan dari `knowledge/*.yaml`. Satu file boleh berisi satu entri atau daftar entri, dan setiap entri divalidasi terhadap `schema/knowledge.v1.json` saat `daysra scan` memuat knowledge base sebelum engine dijalankan.

```yaml
template_id: swagger-api
title: "Dokumentasi API publik dapat diakses"
meaning: "Endpoint dokumentasi API dapat dijangkau dari jaringan yang dipindai."
impact: "Dokumentasi dapat membantu pemetaan permukaan serangan."
verify_steps:
  - "Buka URL yang dilaporkan di browser."
  - "Periksa apakah dokumentasi memang dimaksudkan untuk publik."
concept: "Manajemen permukaan serangan API."
lang: id
```

Validasi semua entri tanpa menjalankan pemindaian:

```sh
PYTHONPATH=src .venv/bin/python -c "from daysra.knowledge import load_knowledge_base; kb = load_knowledge_base(); print(f'{len(kb)} entri valid')"
```

Jika `template_id` tidak punya entri, Daysra memakai fallback generik berdasarkan severity dan menandainya `[fallback generik]` di output. Entri yang tidak valid membuat `daysra scan` berhenti dengan error yang menyebut file dan field.

### 5. Buat Laporan Markdown (`daysra report`)
Hasilkan laporan ringkas hasil recon atau scan dalam format Markdown:

```sh
# Laporan run terakhir yang dicetak ke terminal
daysra report

# Laporan untuk run ID tertentu (recon atau scan)
daysra report --run <RUN_ID>

# Menyimpan laporan ke file
daysra report -o laporan-recon.md
```

#### Contoh laporan scan

Untuk run scan, laporan memuat seksi **Temuan**: jumlah per severity (semuanya 0 bila tidak ada temuan), penjelasan per `template_id` (dari knowledge base yang sama dengan terminal atau fallback generik), daftar `matched_at`, CVE dari tool, dan daftar template yang belum punya entri knowledge base. `evidence` tidak pernah dimasukkan ke laporan maupun keluaran terminal.

```md
# Laporan Scan DAYSRA

## Ringkasan Run

| Parameter | Nilai |
| --- | --- |
| **Target** | `example.com` |
| **Status** | **complete** |
| **Total Temuan** | 2 |

> Daftar host yang dipindai tidak disimpan pada run scan ini. Lihat laporan reconnaissance untuk target yang sama.

## Temuan

### Jumlah Temuan per Severity

| Severity | Jumlah |
| --- | ---: |
| critical | 0 |
| high | 0 |
| medium | 1 |
| low | 0 |
| info | 1 |

### Penjelasan per Template

#### `prometheus-metrics` — Prometheus Metrics - Detect (medium)

**Apa ini:** Endpoint metrik Prometheus dapat diakses
...
**Matched At:**

- https://metrics.example.com/metrics

## Template tanpa entri knowledge base

- `fingerprinthub-web-fingerprints`
```

Jenis laporan ditentukan dari metadata tool yang tersimpan pada run, bukan dari ada/tidaknya temuan: run yang mencatat `nuclei` memakai layout scan (termasuk saat nol temuan), sedangkan run yang mencatat `subfinder`/`httpx` memakai layout reconnaissance lama (ringkasan run, sebaran sumber, daftar subdomain, dan host hidup). Run scan tanpa temuan tetap menampilkan seksi **Temuan** dengan jumlah per severity semuanya `0` disertai peringatan bahwa hasil itu bukan jaminan target aman.

Saat dijalankan, `daysra report` mencetak `Jenis run: <scan|recon> | Run ID: <id>` ke **stderr**, sehingga stdout tetap berupa Markdown bersih yang bisa di-pipe atau diarahkan ke file.
