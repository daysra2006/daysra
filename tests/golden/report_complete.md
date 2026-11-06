# Laporan Reconnaissance DAYSRA

## Ringkasan Run

| Parameter | Nilai |
| --- | --- |
| **Target** | `example.com` |
| **Run ID** | `01JTESTRECON000000000000001` |
| **Status** | **complete** |
| **Total Host Unik** | 2 |
| **Host Hidup (HTTP)** | 1 |
| **Waktu Mulai** | 2026-11-05T10:00:00Z |
| **Waktu Selesai** | 2026-11-05T10:00:04Z |
| **Versi Tool** | httpx `v1.12.0`, subfinder `v2.17.0` |

## Sebaran Sumber Temuan

| Sumber | Jumlah Host |
| --- | ---: |
| crtsh | 2 |
| alienvault | 1 |

## Daftar Subdomain

| No | Hostname | Sumber | Alamat IP |
| ---: | --- | --- | --- |
| 1 | `api.example.com` | alienvault, crtsh | 192.0.2.1 |
| 2 | `web.example.com` | crtsh | - |

## Host Hidup (HTTP)

| No | URL | Status | Judul Halaman | Teknologi |
| ---: | --- | :---: | --- | --- |
| 1 | `https://api.example.com` | 200 | API Gateway | Nginx, Python |

---
*Dibuat oleh DAYSRA pada 2026-11-05T10:00:05Z*
