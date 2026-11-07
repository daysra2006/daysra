# DAYSRA — Design Freeze v1.1

Disusun 5 November 2026 untuk Dayara. Dokumen ini adalah sumber kebenaran tunggal sebelum kode ditulis. Perubahan setelah ini harus lewat revisi dokumen, bukan lewat improvisasi di kode.

**Perubahan v1.1 (5 November 2026):** Daysra tidak memakai LLM. Simple Mode sepenuhnya berbasis knowledge base offline dan metadata dari tool, sehingga deterministik, tanpa jaringan, dan tanpa biaya. Semua rujukan Ollama, provider eksternal, `--no-llm`, dan `--anonymize` dihapus.

## 1. Tujuan dan non-tujuan

**Tujuan.** Daysra adalah lapisan orkestrasi CLI di atas tool keamanan web yang sudah ada (Subfinder, httpx, Nuclei). Ia menghubungkan niat pengguna dengan hasil: perintah sederhana, output ringkas dan terurut, serta penjelasan yang membantu pengguna memahami konsepnya.

**Non-tujuan (v0.x).** Bukan scanner baru. Bukan SaaS. Bukan GUI/TUI. Bukan pengganti tool aslinya. Tidak ada eksploitasi otomatis.

## 2. Batasan mutlak

| # | Batasan | Konsekuensi desain |
| --- | --- | --- |
| B1 | **Biaya uang = 0.** | Hanya perangkat lunak gratis dan lokal. Tidak ada API berbayar, tidak ada langganan. Tanpa LLM. |
| B2 | Penggunaan pribadi, hanya target legal. | Scope wajib dan ditegakkan di kode. |
| B3 | Satu pengembang. | Maksimal dua bahasa, dependensi minimal, tidak ada infrastruktur server. |
| B4 | Kode ditulis oleh Codex (agent), direview oleh Dayara. | Dokumen ini harus cukup jelas agar agent tidak menebak. |

## 3. Keputusan yang dibekukan

| Topik | Keputusan |
| --- | --- |
| Bahasa | **Go** untuk engine, **Python 3.11+** untuk CLI, penyimpanan, penjelasan, laporan. Tidak ada bahasa ketiga di v0.x. |
| Integrasi tool | Engine menjalankan binary Subfinder/httpx/Nuclei sebagai **subprocess dengan output JSON/JSONL**, plus pemeriksaan versi. SDK Go ProjectDiscovery tidak dipakai di v0.x (graf dependensi berat dan API-nya sering berubah). Boleh dievaluasi ulang setelah v0.3. |
| Penyimpanan | **SQLite** (satu file). **Python adalah satu-satunya penulis.** Go hanya menulis JSONL. |
| Kontrak Go↔Python | JSONL berversi (`schema_version`) via stdout engine. |
| LLM | **Tidak ada. Penjelasan Simple Mode berasal dari knowledge base offline dan metadata tool (deterministik)**. |
| CLI | Python: Typer + Rich. |
| Laporan | Markdown via Jinja2. |
| Config | Mengikuti XDG (`~/.config/daysra/config.toml`), data di `~/.local/share/daysra/`. |
| Repo | Monorepo. |

## 4. Arsitektur

```
┌────────────────────────── daysra (Python) ───────────────────────────┐
│ CLI (Typer)  →  Orchestrator  →  Ingestor ──► SQLite (penulis tunggal)│
│                      │                │                               │
│                      │                └──► Report (Jinja2) / Simple Mode│
│                      ▼                                  │              │
│            spawn subprocess                    Explainer (Knowledge Base)│
└──────────────────────┼───────────────────────────────────────────────┘
                       ▼  JSONL via stdout, log via stderr
┌──────────────── daysra-engine (Go) ──────────────────┐
│ Scope guard → Runner (goroutine pool, rate limit)      │
│   → Adapter: subfinder | httpx | nuclei (subprocess)   │
│   → Normalizer → emit JSONL events                     │
└────────────────────────────────────────────────────────┘
```

Pembagian tanggung jawab: **Go** menangani concurrency, scope, proses eksternal, dan normalisasi. **Python** menangani tampilan, penyimpanan, riwayat, penjelasan, dan laporan.

## 5. Struktur repo

```
daysra/
├── AGENTS.md                 # aturan untuk Codex (lihat bagian 16)
├── docs/DESIGN_FREEZE.md     # dokumen ini
├── schema/                   # JSON Schema kontrak (sumber kebenaran)
│   ├── event.v1.json
│   └── knowledge.v1.json
├── engine/                   # Go module: daysra-engine
│   ├── cmd/daysra-engine/
│   └── internal/{scope,runner,adapters,normalize,emit}/
├── src/daysra/               # Python package
│   ├── cli/  core/  ingest/  store/  report/  simple/
├── knowledge/                # knowledge base offline (YAML)
├── tests/
│   ├── fixtures/{subfinder,httpx,nuclei}/<versi>/
│   └── golden/
├── Makefile                  # build, test, lint, doctor
└── pyproject.toml
```

## 6. Kontrak data

### 6.1 Format event (satu baris JSON per event)

```json
{"schema_version":"1","type":"host","run_id":"01J...","ts":"2026-11-05T10:00:00Z","data":{}}
```

`type` ∈ `run_start`, `host`, `http`, `finding`, `progress`, `warning`, `run_end`.

### 6.2 Model inti

**Run:** `run_id` (ULID), `target`, `scope_hash`, `started_at`, `finished_at`, `status` (`complete` / `partial` / `failed` / `cancelled`), `tool_versions{}`.

**Host:** `hostname` (huruf kecil, tanpa titik akhir, IDNA/punycode), `ips[]`, `sources[]`. ID host = `sha256(hostname)` agar stabil antar-run.

**Http (observasi httpx):** `hostname`, `url`, `status_code`, `title`, `tech[]`, `content_length`, `tls_issuer` (opsional).

**Finding:** `template_id`, `name`, `severity` (`info|low|medium|high|critical`, **dari tool**), `cve[]`, `matched_at`, `evidence` (dipotong maksimal 2 KB, rahasia disamarkan), `tool`, `tool_version`. ID finding = `sha256(hostname | template_id | matcher | path)`.

### 6.3 Skema SQLite

| Tabel | Isi |
| --- | --- |
| `runs` | metadata run |
| `hosts` | host unik (`id`, `hostname`, `first_seen_run`, `last_seen_run`) |
| `host_obs` | observasi host per run (ips, sources) |
| `http_obs` | observasi HTTP per run |
| `findings` | finding unik (`id`, `first_seen_run`, `last_seen_run`, `status`) |
| `finding_obs` | observasi finding per run |
| `explanations` | `dicadangkan, tidak dipakai di v1.1` |

Diff antar-run (baru, hilang, tetap) dihitung dari `*_obs`. Migrasi memakai `PRAGMA user_version` dan skrip berurutan.

### 6.4 Protokol engine

```
daysra-engine recon --target example.com --scope scope.yaml --run-id <ulid>
```

- stdout: hanya event JSONL. stderr: log manusia.
- Exit code: `0` sukses, `2` pelanggaran scope, `3` tool tidak ditemukan atau versi tidak didukung, `4` hasil parsial, `130` dibatalkan.
- Menerima SIGINT: berhenti rapi, mengirim `run_end` dengan status `cancelled` atau `partial`.

`daysra-engine show-command <recon|probe|scan>` adalah subcommand metadata non-run yang mencetak satu objek JSON sesuai `schema/show-command.v1.json`, bukan event.

## 7. Scope dan keamanan operasional

`scope.yaml` wajib untuk setiap run:

```yaml
authorization: "domain milik sendiri / lab / bug bounty <nama program>"
allow: ["example.com", "*.example.com"]
deny:  ["admin.example.com"]
max_rate: 50        # request per detik, default konservatif
timeout: 600        # detik per tahap
```

- Field `authorization` tidak boleh kosong. Daysra menolak berjalan tanpanya.
- Scope ditegakkan **dua kali**: preflight di Python, penegakan keras di Go (setiap host yang ditemukan difilter sebelum diteruskan ke tahap berikutnya).
- Subprocess selalu memakai array argumen, **tidak pernah** shell. Input target divalidasi sebagai hostname sebelum dipakai.
- Tidak ada mode eksploitasi. Template Nuclei dibatasi ke kategori non-destruktif secara default (tanpa `dos`, `fuzz` agresif, brute force).

`timeout` pada scope adalah **batas total satu tahap** (recon, probe, atau scan), bukan timeout per request. Adapter selalu meneruskan timeout per request yang kecil dan tetap ke flag `-timeout` tool (Subfinder 30 detik, httpx 10 detik, Nuclei 10 detik, sesuai default versi terpasang), sedangkan `scope.Timeout` dipakai sebagai `runner.Options.Timeout` untuk keseluruhan tahap. Karena itu total timeout scan tidak dikalikan dengan jumlah URL. Jika batas tahap habis, hasil sejauh ini tetap disimpan dengan status `partial` dan exit code 4 (lihat bagian 12).

## 8. Simple Mode (tanpa LLM)

**Prinsip:** Simple Mode **deterministik**: tanpa LLM, tanpa jaringan, tanpa biaya. Penjelasan hanya berasal dari knowledge base buatan sendiri dan metadata yang dikirim tool.

### 8.1 Lapisan penjelasan

1. **Knowledge base offline** (`knowledge/*.yaml`): penjelasan per `template_id` populer dan per kategori: arti, dampak, langkah verifikasi, konsep yang perlu dipelajari. Tiap entri divalidasi terhadap `schema/knowledge.v1.json` saat dimuat. Ditulis sekali, akurat, deterministik.
2. **Metadata tool:** jika `template_id` belum punya entri, pakai deskripsi, remediation, dan referensi dari template itu sendiri (bila ada di output; verifikasi per bagian 15).
3. **Fallback generik** berdasarkan severity dan tag: penjelasan umum kategori beserta langkah verifikasi standar. Setiap temuan selalu mendapat penjelasan, dan yang jatuh ke fallback ditandai di laporan agar entri baru bisa ditulis.

### 8.2 Aturan keamanan tampilan (wajib)

1. **Output tool dan target adalah data tak tepercaya.** Hapus karakter kontrol dan urutan escape ANSI/terminal dari semua data target (banner, title, header, isi respons) sebelum dicetak, agar target tidak bisa memanipulasi terminal pengguna.
2. Teks dari target di-escape sebelum dirender oleh Rich dan di dalam laporan Markdown (tanpa markup atau link aktif yang dikendalikan target).
3. **Fakta selalu dari tool.** Severity, CVE, dan `template_id` tidak pernah dikarang atau diubah oleh Daysra.
4. `evidence` dipotong maksimal 2 KB dan rahasia disamarkan oleh satu pass redaksi yang sama untuk semua jalur keluaran.
5. Entri knowledge base yang tidak lolos validasi skema ditolak saat dimuat dengan pesan jelas, tidak diabaikan diam-diam.
6. Knowledge base ditulis dalam bahasa Indonesia; field `lang` disiapkan untuk bahasa lain.

### 8.3 Perilaku Simple Mode

- Perintah berbasis niat: `daysra recon example.com`.
- Output Rich: ringkasan jumlah per severity, tabel temuan terurut prioritas, tanpa log mentah.
- Setiap temuan punya blok "Apa ini / Kenapa penting / Langkah berikutnya / Konsep untuk dipelajari".
- `--show-command` menampilkan command asli tool yang dijalankan, agar pengguna tetap belajar sintaks aslinya. `--raw` menampilkan output mentah.

## 9. Alur data

```
daysra recon <domain>
  → muat config + scope.yaml → preflight
  → spawn daysra-engine → baca event JSONL (progress langsung tampil)
  → Ingestor: validasi skema → upsert SQLite (satu transaksi per run)
  → Explainer: knowledge base → metadata tool → fallback generik
  → Simple Mode di terminal + laporan Markdown
```

Jika engine crash, run tetap disimpan dengan status `partial` dan ditandai di laporan. Hasil parsial tidak pernah dianggap lengkap.

## 10. Spesifikasi CLI

| Perintah | Fungsi |
| --- | --- |
| `daysra doctor` | Cek Go engine, subfinder/httpx/nuclei (ada dan versi), izin file config |
| `daysra init` | Buat config dan contoh `scope.yaml` |
| `daysra recon <domain>` | Enumerasi subdomain (M1), lalu probing httpx (M2) |
| `daysra scan <domain>` | Nuclei pada host yang hidup (M3) |
| `daysra report [--run ID]` | Buat laporan Markdown |
| `daysra history` / `daysra diff A B` | Riwayat dan perbandingan run (M5) |
| `daysra explain <finding-id>` | Penjelasan mendalam satu temuan |

Flag global: `--raw`, `--show-command`, `--scope FILE`, `--lang`.

## 11. Konfigurasi dan rahasia

- `config.toml` berizin `0600`. Daysra menolak berjalan jika izinnya terlalu longgar (dengan pesan perbaikan).
- API key provider Subfinder tetap dikelola di file config Subfinder sendiri; Daysra **tidak menduplikasinya**.
- Kunci dan token tidak boleh muncul di log, laporan, atau fixture. Ada pass redaksi tunggal yang dipakai semua jalur keluaran.

## 12. Penanganan error

| Kejadian | Perilaku |
| --- | --- |
| Tool tidak ada / versi tidak didukung | Exit 3, pesan jelas, arahkan ke `daysra doctor` |
| Skema output tool berubah | Adapter gagal dengan pesan versi, tidak menebak |
| Timeout tahap | Simpan hasil sejauh ini, status `partial` |
| Ctrl+C | Hentikan proses anak, simpan parsial, status `cancelled` |
| Entri knowledge base tidak ada | Pakai metadata tool, lalu fallback generik; tandai di laporan |
| Binary `httpx` salah (CLI Python `httpx` di PATH) | `doctor` mendeteksi lewat banner versi dan menolak |

## 13. Strategi pengujian

- **Unit:** validasi scope, normalisasi hostname, hashing ID, redaksi rahasia, sanitasi ANSI/karakter kontrol.
- **Adapter:** fixture output asli per versi tool; parser diuji terhadap fixture, bukan terhadap internet.
- **Kontrak:** JSON Schema di `schema/` divalidasi dari kedua sisi (Go dan Python).
- **Golden test:** laporan Markdown dibandingkan dengan file acuan.
- **Knowledge base:** semua entri lolos validasi skema; `template_id` tanpa entri jatuh ke fallback; data target berisi escape ANSI tidak lolos ke output.
- **End-to-end:** hanya terhadap target legal dan gratis: lab lokal (OWASP Juice Shop dan DVWA via container) dan domain milik sendiri. CI tidak boleh menyentuh internet.

## 14. Milestone

| M | Isi | Kriteria selesai | Status |
| --- | --- | --- | --- |
| M0 | Skeleton repo, schema/, Makefile, CI lokal, `daysra --version`, `daysra doctor` | `make test` hijau | Selesai |
| M1 | Domain → scope → Subfinder → normalisasi → SQLite → laporan Markdown | Run lengkap pada domain uji, test hijau, partial/cancel teruji | Selesai |
| M2 | Adapter httpx, observasi HTTP, laporan diperkaya | Fixture dua versi httpx lolos | Selesai |
| M3 | Adapter Nuclei, finding, severity dari tool | Temuan terdedupe dengan ID stabil | Selesai (7 November 2026) |
| M4 | Simple Mode penuh: knowledge base, fallback generik, sanitasi output | `Test sanitasi dan fallback lolos` | Belum dimulai |
| M5 | History dan diff antar-run | Diff benar pada dua run uji | Belum dimulai |

**Estimasi:** karena ada lapisan Go↔Python, naikkan estimasi spesifikasi v0.2 sekitar 15–25%. Anggap rentang realistis ±220–310 jam dan perlakukan sebagai perkiraan kasar, bukan janji. Mulai ukur jam aktual sejak M0.

## 15. Risiko dan hal yang harus diverifikasi

Hal-hal berikut **tidak boleh diasumsikan** oleh agent coding. Verifikasi terhadap versi yang terpasang di mesin sebelum menulis adapter:

1. Nama flag output JSON dan JSONL tiap tool (Subfinder, httpx, Nuclei) pada versi terpasang.
2. Nama field di output tiap tool; simpan sebagai fixture bertanda versi.
3. Perilaku tool saat menerima SIGINT.
4. Lokasi config dan template Nuclei di sistem Arch/Omarchy.
5. Field deskripsi dan remediation pada output Nuclei versi terpasang (untuk fallback penjelasan).

| Risiko | Mitigasi |
| --- | --- |
| Perubahan format tool | Fixture berversi, pemeriksaan versi, gagal jelas |
| Karakter kontrol/ANSI dari target | Bagian 8.2 |
| Jam kerja membengkak | Milestone kecil, M1 harus berdiri sendiri |
| Knowledge base tidak lengkap | Fallback generik; entri ditambah bertahap dari temuan nyata |
| Kode dari agent tidak dipahami | Satu langkah per sesi, review diff, test wajib |

## 16. Aturan kerja untuk Codex (salin ke `AGENTS.md`)

```
# Aturan proyek DAYSRA
Baca docs/DESIGN_FREEZE.md sebelum mengubah apa pun. Dokumen itu mengikat.

1. Kerjakan SATU milestone/langkah per sesi. Jangan melompati urutan.
2. Bahasa: Go untuk engine/, Python 3.11+ untuk src/. Dilarang menambah bahasa lain.
3. Dilarang shell=True atau eksekusi lewat shell. Subprocess selalu array argumen.
4. Dilarang menambah layanan berbayar atau dependensi yang membutuhkan akun berbayar. Dilarang memakai LLM dalam bentuk apa pun.
5. Python adalah satu-satunya penulis SQLite. Go hanya menulis JSONL.
6. Setiap perubahan kontrak wajib memperbarui schema/ dan test di kedua sisi.
7. Setiap adapter wajib punya fixture bertanda versi dan test. Jangan menebak format output tool; verifikasi pada versi terpasang.
8. Output tool/target diperlakukan sebagai data tak tepercaya, dan disanitasi sebelum dicetak atau masuk laporan.
9. Severity, CVE, template_id berasal dari tool, tidak pernah dikarang atau diubah oleh Daysra.
10. Rahasia tidak boleh masuk log, laporan, cache, atau fixture.
11. Test tidak boleh mengakses internet.
12. Selesai satu langkah: jalankan make test dan make lint, lalu tulis ringkasan perubahan dan hal yang belum pasti. Jangan menambah fitur di luar langkah.
13. Jika spesifikasi ambigu atau bertentangan dengan kenyataan di mesin, berhenti dan laporkan, jangan berimprovisasi.
```

## 17. Langkah berikutnya

1. Simpan dokumen ini sebagai `docs/DESIGN_FREEZE.md` dan bagian 16 sebagai `AGENTS.md`.
2. Berikan Codex **hanya M0**. Review hasilnya sebelum M1.
3. Jalankan verifikasi bagian 15 di mesin Dayara dan simpan keluarannya sebagai fixture pertama.
