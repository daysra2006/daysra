# Laporan Scan DAYSRA

> [!WARNING]
> **PERINGATAN: Run ini berstatus Parsial (Tidak Lengkap).**
> Proses pengumpulan data terputus atau mengalami batas waktu (timeout). Data di bawah ini hanya mencerminkan hasil sementara yang berhasil diamati.

## Ringkasan Run

| Parameter | Nilai |
| --- | --- |
| **Target** | `partial.example.com` |
| **Run ID** | `01JTESTSCAN0000000000000002` |
| **Status** | **partial** |
| **Total Temuan** | 1 |
| **Waktu Mulai** | 2026-11-05T11:10:00Z |
| **Waktu Selesai** | 2026-11-05T11:10:02Z |
| **Versi Tool** | nuclei `v3.11.1` |

> Daftar host yang dipindai tidak disimpan pada run scan ini. Lihat laporan reconnaissance untuk target yang sama.

## Temuan

### Jumlah Temuan per Severity

| Severity | Jumlah |
| --- | ---: |
| critical | 0 |
| high | 0 |
| medium | 0 |
| low | 0 |
| info | 1 |

### Penjelasan per Template

#### `tech-detect` — Wappalyzer Technology Detection (info)

**Apa ini:** Teknologi web terdeteksi

**Kenapa penting:** Informasi teknologi membantu pemetaan dan dapat memengaruhi prioritas pemeliharaan. Temuan ini sendiri bukan bukti kerentanan.

**Langkah berikutnya:**

1. Buka halaman yang sama dan bandingkan petunjuk teknologi yang terlihat.
2. Cocokkan dengan inventaris teknologi yang dikelola oleh tim aplikasi.
3. Gunakan informasi ini untuk memeriksa pembaruan, bukan untuk menyimpulkan adanya kerentanan.

**Konsep untuk dipelajari:** Deteksi teknologi (fingerprinting) dan manajemen inventaris perangkat lunak.

**Matched At:**

- https://web.example.com

## Template tanpa entri knowledge base

*Semua template pada run ini memiliki entri knowledge base.*

---
*Dibuat oleh DAYSRA pada 2026-11-05T11:10:03Z*
