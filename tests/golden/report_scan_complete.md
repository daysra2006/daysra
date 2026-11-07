# Laporan Scan DAYSRA

## Ringkasan Run

| Parameter | Nilai |
| --- | --- |
| **Target** | `example.com` |
| **Run ID** | `01JTESTSCAN0000000000000001` |
| **Status** | **complete** |
| **Total Temuan** | 4 |
| **Waktu Mulai** | 2026-11-05T11:00:00Z |
| **Waktu Selesai** | 2026-11-05T11:00:05Z |
| **Versi Tool** | nuclei `v3.11.1` |

> Daftar host yang dipindai tidak disimpan pada run scan ini. Lihat laporan reconnaissance untuk target yang sama.

## Temuan

### Jumlah Temuan per Severity

| Severity | Jumlah |
| --- | ---: |
| critical | 0 |
| high | 0 |
| medium | 1 |
| low | 0 |
| info | 3 |

### Penjelasan per Template

#### `prometheus-metrics` — Prometheus Metrics - Detect (medium)

**Apa ini:** Endpoint metrik Prometheus dapat diakses

**Kenapa penting:** Metrik dapat mengungkap informasi operasional seperti nama layanan, jumlah permintaan, atau status internal. Dampaknya bergantung pada isi metrik dan siapa yang seharusnya boleh mengaksesnya.

**Langkah berikutnya:**

1. Buka endpoint metrik yang dilaporkan di browser atau klien HTTP biasa.
2. Periksa apakah endpoint tersebut memang perlu dapat diakses dari jaringan saat ini.
3. Tinjau apakah metrik memuat informasi sensitif yang tidak diperlukan untuk pemantauan.

**Konsep untuk dipelajari:** Eksposur telemetri dan prinsip akses minimum ke sistem pemantauan.

**CVE:** CVE-2026-0001
**Matched At:**

- https://metrics.example.com/metrics

#### `fingerprinthub-web-fingerprints` — FingerprintHub Technology Fingerprint (info) [fallback generik]

**Apa ini:** Temuan informasi

**Kenapa penting:** Dampak langsung biasanya rendah, tetapi informasi ini dapat membantu pihak yang tidak berwenang merencanakan langkah berikutnya.

**Langkah berikutnya:**

1. Tinjau konteks endpoint yang dilaporkan pada tabel temuan.
2. Konfirmasi apakah informasi tersebut memang seharusnya dapat diakses publik.
3. Bandingkan dengan kebijakan eksposur organisasi.

**Konsep untuk dipelajari:** Pemetaan permukaan serangan (attack surface) dan klasifikasi informasi.

**Matched At:**

- https://web.example.com

#### `swagger-api` — Public Swagger API - Detect (info)

**Apa ini:** Dokumentasi API publik dapat diakses

**Kenapa penting:** Dokumentasi API dapat mengungkap daftar endpoint, parameter, dan struktur data yang membantu pemetaan permukaan serangan. Dampaknya bergantung pada apakah dokumentasi tersebut memang dimaksudkan untuk publik.

**Langkah berikutnya:**

1. Buka URL yang dilaporkan di browser pada lingkungan yang sah.
2. Periksa apakah dokumentasi memang disediakan untuk publik atau seharusnya dibatasi.
3. Tinjau apakah dokumentasi memuat informasi internal yang tidak perlu diungkapkan.

**Konsep untuk dipelajari:** Manajemen permukaan serangan API dan prinsip least privilege.

**Matched At:**

- https://api.example.com/api-docs/swagger.json
- https://web.example.com/swagger.json

## Template tanpa entri knowledge base

Template berikut memakai fallback generik. Tambahkan entri di direktori `knowledge/` agar penjelasannya lebih spesifik.

- `fingerprinthub-web-fingerprints`

---
*Dibuat oleh DAYSRA pada 2026-11-05T11:00:06Z*
