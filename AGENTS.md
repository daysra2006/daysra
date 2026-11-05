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
11. 11. Test tidak boleh mengakses internet dan tidak boleh memindai target apa pun. Memasang dependensi dev gratis dari PyPI hanya ke .venv (tanpa sudo) diizinkan jika dibutuhkan tugas; sebutkan paket dan versinya di laporan.
12. Selesai satu langkah: jalankan make test dan make lint, lalu tulis ringkasan perubahan dan hal yang belum pasti. Jangan menambah fitur di luar langkah.
13. Jika spesifikasi ambigu atau bertentangan dengan kenyataan di mesin, berhenti dan laporkan, jangan berimprovisasi
14. Setelah menyelesaikan satu langkah bertanda "Langkah N", BERHENTI dan tunggu balasan "next". Dilarang mengerjakan langkah berikutnya tanpa balasan itu, walaupun prompt memuat semua langkah.
15. Komponen penjaga keamanan (scope) bersifat fail-closed: input yang tidak dikenali atau ambigu harus menghasilkan error atau penolakan, tidak pernah diabaikan diam-diam
16. Agent dilarang menjalankan subfinder, httpx, atau nuclei terhadap target apa pun kecuali pemilik repo menyebut satu domain secara eksplisit di prompt dan menyatakan itu miliknya; di luar itu hanya -version dan -h yang boleh.
17. httpx tidak boleh mengikuti redirect. Setiap hostname dari hasil httpx (host, url, dan final URL) diperiksa ulang oleh scope sebelum disimpan; yang di luar scope dibuang dengan event warning.
18. Nuclei: wajib -duc (tanpa cek update), tanpa OAST/interactsh, tanpa follow redirect, kecualikan tag intrusif, rate limit dari scope; jangan pernah menjalankan template di luar direktori template resmi.

