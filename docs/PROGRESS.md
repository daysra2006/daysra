# Progres DAYSRA

Tanggal: 2026-11-05

## M0

- [x] Struktur repo, README, dan `.gitignore`
- [x] CLI Python: `daysra --version` dan `daysra doctor`
- [x] Engine Go dan validasi scope
- [x] JSON Schema dan fixture kontrak
- [x] Makefile: build, test, lint, doctor

## M0.1

- [x] Langkah A: Parse versi doctor dari keluaran bercampur + fixture versi nyata (subfinder, httpx, nuclei)
- [x] Langkah B: Audit dan perkuat internal/scope (wildcard subdomain-only, pencocokan label domain, penolakan IP literal/invalid, table-driven tests)
- [x] Langkah C: Pembaruan catatan adapter dan progres M0.1

## M0.2

- [x] Langkah 1: Parser YAML ketat (gopkg.in/yaml.v3 v3.0.1) dengan decoder.KnownFields(true), fail-closed, dan nilai default
- [x] Langkah 1b: Perbaikan celah fail-open (tolak dokumen kedua dan entri null/kosong pada allow/deny)
- [x] Langkah 2: Kasus tepi hostname (batas panjang label > 63, total > 253, hyphen batas, label kosong, karakter non-ASCII, target wildcard ditolak)

## Catatan adapter

- `nuclei -version` menulis versi ke stderr (stdout kosong), warning sonic muncul di stderr.
- `subfinder -version` menulis versi dan direktori konfigurasi ke stderr (stdout kosong).
- `httpx -version` menulis banner ProjectDiscovery dan versi ke stderr (stdout kosong).
- Aturan: adapter M1 dan M2 wajib membaca stdout (data) dan stderr (log) terpisah.

## M1

- [x] Langkah 1: Engine Go, emit event JSONL dan normalisasi hostname (punycode IDN via `golang.org/x/net/idna`, deduplikasi, penggabungan sumber, dan CLI `check-scope`)
- [x] Langkah 2: Engine Go, runner subprocess aman dan adapter Subfinder (pemisahan stdout/stderr, penerusan SIGINT, timeout dari scope, exit code 0, 2, 3, 4, 130, fixture output nyata)
- [x] Langkah 3: Python, SQLite store (tabel `runs`, `hosts`, `host_obs`, migrasi `PRAGMA user_version`), generator ULID independen, dan Ingestor transaksi tunggal per run
- [x] Langkah 4: Python, CLI `daysra init` dan `daysra recon` (preflight check-scope lewat engine, streaming event dengan Rich progress, Simple Mode summary, penanganan Ctrl+C rapi)
- [x] Langkah 5: Laporan Markdown Jinja2 (`daysra report [--run ID]`, tabel ringkasan, sebaran sumber, daftar subdomain, sanitasi kontrol ANSI, dan golden test acuan)
- [x] Langkah 6: Penutup M1, dokumentasi cara pakai recon pada README, dan verifikasi suite pengujian lengkap

## M2

- [x] Langkah 1: Adapter httpx (Go) di `internal/adapters/httpx` dan subcommand `daysra-engine probe` (argumen `-silent -json -sc -title -td -cl`, rate limit dan timeout dari scope, pemisahan stdout/stderr, host via stdin, filter pre/post-probe scope, penanganan timeout & SIGINT)
- [x] Langkah 2: Penyimpanan Python di `daysra.store` (`http_obs`, migrasi `PRAGMA user_version = 2`, backward compatibility DB v1, dan ingestor event `http`)
- [x] Langkah 3: Integrasi CLI `daysra recon` (tahap recon lalu probe pada host hasil temuan, flag `--no-probe`, progress Rich per tahap, penanganan partial jika probe gagal/batal, Simple Mode dengan ringkasan host hidup, sebaran status code, 10 teknologi teratas, dan status menarik)
- [x] Langkah 4: Laporan Markdown diperkaya bagian host hidup (`url`, `status`, `title`, `teknologi`) serta tanda parsial, golden test diperbarui, dan penutup M2

## M3

- [x] Langkah 0: Audit M2, izin end-to-end khusus, dan penambahan Aturan 18 (nuclei) pada AGENTS.md
- [x] Langkah 1: Fixture output nuclei v3.11.1 nyata dari lab lokal (13 baris JSONL, pemisahan stdout/stderr, derived dataset hostname)
- [x] Langkah 2: Adapter nuclei (Go) di `internal/adapters/nuclei`, subcommand `daysra-engine scan`, redaksi bukti sensitif, pemotongan bukti 2 KB, penolakan kebocoran request/response
- [x] Langkah 2b: Profil scan bawaan tanpa default-login (`tech,exposure,misconfig`), opsi `--include-tags`, penolakan etags terlarang
- [x] Langkah 3: Penyimpanan Python di `daysra.store` (`findings`, `finding_obs`, migrasi `PRAGMA user_version = 3`, ingestor event `finding`, deduplikasi temuan)
- [ ] Langkah 4: CLI `daysra scan DOMAIN`, Simple Mode temuan kerentanan, dan seksi temuan laporan Markdown
- [ ] Langkah 5: Penutup M3, pembaruan dokumentasi, dan verifikasi akhir suite pengujian

## Catatan M3

- `daysra scan --include-tags` yang memuat default-login wajib meminta konfirmasi terpisah dengan mengetik kata "default-login", dan flag --yes TIDAK boleh melewatinya (hanya flag khusus --accept-default-login yang boleh). Tanpa konfirmasi, tag itu dibuang dan peringatan dicetak.

