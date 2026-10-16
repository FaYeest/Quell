# Product Requirements Document (PRD): Quell

* **Nama Produk:** Quell (`quell.sh` / `quell.dev`)
* **Kategori:** B2B DevSecOps / Autonomous AI Security Engineer SaaS
* **Versi Dokumen:** 1.0 (MVP Blueprint)
* **Target Pasar:** Startup Teknologi, Software House / Dev Agency, Solo Founder / Indie Hacker

---

## 1. Executive Summary & Product Vision

### 1.1 Deskripsi Singkat
**Quell** adalah platform *Autonomous AI Security Engineer* berbasis SaaS yang terintegrasi langsung ke dalam repositori GitHub/GitLab pengguna untuk mendeteksi celah keamanan secara otomatis, memvalidasi tingkat bahayanya menggunakan konteks lintas-file (*Graph-based Code RAG*), dan **langsung mengirimkan solusi perbaikan kode melalui Pull Request (PR) yang siap di-*merge***.

### 1.2 Tagline Produk
> *"Stop drowning in security alerts. Quell finds real vulnerabilities in your codebase and ships the fix before attackers can exploit them."*

### 1.3 Pernyataan Masalah (Problem Statement)
1. **Alert Fatigue (Kelelahan Peringatan):** Alat pemindai tradisional (seperti SonarQube atau Snyk standar) menghasilkan ratusan peringatan yang hingga $60\%$–$80\%$ di antaranya merupakan *false positive* karena tidak memahami konteks arsitektur kode secara menyeluruh.
2. **Beban Remediasi pada Developer:** Alat keamanan lama hanya memberi tahu *di mana* letak masalahnya, tetapi *developer* tetap harus meluangkan waktu berjam-jam untuk meriset dan menulis kode perbaikannya sendiri di tengah kejaran *deadline* fitur.
3. **Biaya Pentest Manual yang Mahal & Lambat:** Menyewa jasa *penetration testing* eksternal memakan biaya Rp 25.000.000 hingga Rp 100.000.000+ per sesi, memakan waktu berminggu-minggu, dan hasilnya langsung usang saat ada *commit* kode baru keesokan harinya.
4. **Gelombang Kode AI yang Rentan:** Semakin banyak *developer* dan *founder* menggunakan AI *code generator* (*vibe coding*) yang cepat membangun fitur, tetapi sering meninggalkan celah keamanan fatal seperti *broken access control* (IDOR), *SQL Injection*, dan kebocoran *API key*.

### 1.4 Solusi & Nilai Jual Unik (Unique Value Proposition)
* **Zero Noise, Validated Only:** Quell menelusuri alur data dari *router*, *middleware*, hingga *controller* dan *database query*. Jika sebuah *endpoint* sudah dilindungi oleh *middleware* autentikasi di file lain, Quell tidak akan membunyikan alarm palsu.
* **Actionable Auto-PR (`quell-bot`):** Alih-alih memberikan laporan PDF pasif, Quell bertindak layaknya *Senior Security Engineer* yang langsung membuka *Pull Request* berisi *patch* kode yang mengikuti *coding style* proyek tersebut.
* **Harga Terjangkau untuk Skala Kecil-Menengah:** Biaya berlangganan bulanan yang setara dengan $5\%$ dari gaji satu orang *Security Engineer* penuh waktu.

---

## 2. Target Pelanggan & User Personas

| Persona | Profil & Skala Bisnis | Pain Point Utama | Alasan Membeli Quell |
| :--- | :--- | :--- | :--- |
| **1. The Scaling CTO** | CTO / Lead Dev di Startup (Fintech, SaaS, Healthtech) dengan 5–30 *engineer*. | Harus lulus audit ISO 27001 / UU PDP untuk klien B2B, tapi tidak punya tim *AppSec* khusus. | Mengotomatiskan kepatuhan keamanan kode di setiap *Pull Request* tanpa memperlambat *sprint* tim. |
| **2. The Agency Owner** | Pemilik *Software House* yang mengerjakan 5–15 proyek klien bersamaan. | Klien menuntut jaminan keamanan aplikasi sebelum serah terima proyek (*handover*). | Menjadikan laporan keamanan Quell sebagai nilai tambah (*upsell*) kepada klien agensi. |
| **3. The Vibe Coder / Indie Founder** | Solo developer yang membangun SaaS dengan bantuan AI (Cursor, Claude, Copilot). | Tidak memahami detail keamanan siber; takut aplikasi dibobol atau tagihan cloud membengkak. | Penjaga gawang otomatis yang memperbaiki celah keamanan sebelum kode masuk ke *production*. |

---

## 3. End-to-End User Flow (Alur Kerja Produk)

1. **Onboarding (Kurang dari 2 Menit):**
   * Pengguna mendaftar di *dashboard* Quell menggunakan akun GitHub/GitLab (OAuth).
   * Pengguna menginstal aplikasi `quell-bot` ke repositori yang dipilih dengan 1 klik.
2. **Trigger & Code Indexing:**
   * Setiap kali ada *event* `git push` atau pembuatan *Pull Request* baru (atau jadwal pemindaian berkala), Quell menerima *webhook*.
   * *Worker* Quell menarik perubahan kode ke dalam *ephemeral sandbox* (kontainer sementara) dan memetakan *Abstract Syntax Tree* (AST) untuk memahami hubungan antar-fungsi.
3. **Hybrid Scanning & RAG Validation:**
   * **Tahap 1 (Deterministic Scan):** Pemindaian cepat untuk mendeteksi pola bahaya awal (*hardcoded secrets*, *vulnerable dependencies*, pola *raw query*, XSS, SSRF).
   * **Tahap 2 (Contextual AI Triage):** Agen AI memeriksa file terkait (misal: mengecek apakah variabel `req.user.id` sudah divalidasi di `authMiddleware.ts`). Jika terbukti aman, temuan dibuang secara otomatis.
4. **Auto-Remediation (Pembuatan Patch):**
   * Untuk celah yang tervalidasi nyata, AI menulis ulang blok kode yang rentan menjadi kode yang aman dengan tetap mempertahankan gaya penulisan (*linter rules*, penamaan variabel, dan *framework*) milik pengguna.
5. **Delivery (Pull Request & Notifikasi):**
   * `quell-bot` membuka *Pull Request* khusus di GitHub pengguna berisi penjelasan celah, tingkat keparahan (*Severity*: Critical/High/Medium), dan *diff* kode perbaikannya.
   * Pengguna cukup meninjau dan menekan tombol **Merge Pull Request**.

---

## 4. Spesifikasi Fitur & Ruang Lingkup (Product Scope)

### 4.1 Fase P0 — Minimum Viable Product (Target: Minggu 1–8)
Fokus utama: Menghasilkan nilai inti (*Auto-PR*) dan siap menerima pembayaran pelanggan pertama.

| ID | Fitur | Deskripsi Fungsional | Kriteria Penerimaan (Acceptance Criteria) |
| :--- | :--- | :--- | :--- |
| **F-01** | **GitHub App Integration** | Otentikasi OAuth dan instalasi GitHub App untuk membaca repositori dan membuat PR. | Pengguna dapat menghubungkan repo privat dalam $\le 3$ klik. |
| **F-02** | **AST Code Chunker & RAG** | Memecah kode berdasarkan struktur fungsi/kelas menggunakan *Tree-sitter* untuk konteks lintas-file. | Mendukung bahasa populer: JavaScript/TypeScript (Node.js, Next.js), Python, dan Go. |
| **F-03** | **Core Vulnerability Engine** | Deteksi OWASP Top 10 di level kode: SQL Injection, NoSQLi, IDOR / Broken Auth, XSS, SSRF, dan Hardcoded Secrets. | Tingkat *false positive* di bawah $10\%$ pada *benchmark* pengujian internal. |
| **F-04** | **Automated PR Generator** | Bot membuat *branch* baru (`quell/fix-sqli-auth`) dan mengajukan PR lengkap dengan penjelasan teknis. | Kode hasil *patch* tidak merusak *syntax* (*valid AST*) dan mengikuti struktur *import* proyek. |
| **F-05** | **Web Dashboard & Billing** | Halaman ringkasan skor keamanan, daftar celah yang berhasil diperbaiki, dan integrasi pembayaran. | Terintegrasi dengan *payment gateway* (Stripe/LemonSqueezy & Midtrans) dengan pembatasan kuota per tier. |

### 4.2 Fase P1 — Ekspansi & PLG (Target: Bulan 3–4)
* **F-06: Quell CLI (`$ quell scan` & `$ quell fix`):** Alat terminal ringan untuk dijalankan secara lokal oleh *developer* sebelum melakukan *commit*.
* **F-07: Active API Surface Recon (DAST Lite):** Memindai URL *staging* pengguna dari luar untuk mendeteksi masalah konfigurasi CORS, *security headers* yang hilang, dan *shadow API*.
* **F-08: Integrasi GitLab & Bitbucket:** Memperluas jangkauan pasar ke perusahaan yang tidak menggunakan GitHub.

### 4.3 Fase P2 — Enterprise & Kepatuhan (Target: Bulan 5–6)
* **F-09: One-Click Compliance Exporter:** Menghasilkan laporan audit keamanan berformat PDF resmi untuk lampiran kepatuhan ISO 27001, SOC2, dan UU PDP Indonesia.
* **F-10: BYOK (Bring Your Own Key) & Self-Hosted Agent:** Opsi bagi perusahaan *enterprise* agar pemrosesan kode berjalan sepenuhnya di infrastruktur cloud mereka sendiri.

---

## 5. Contoh Output `quell-bot` pada GitHub Pull Request

Berikut adalah simulasi tampilan deskripsi *Pull Request* otomatis yang dibuat oleh Quell di repositori pelanggan:

> ### 🛡️ [Quell Security Patch] High Severity: Broken Object Level Authorization (IDOR)
> 
> **Ringkasan Temuan:**
> Endpoint `GET /api/v1/invoices/:invoiceId` pada file `src/controllers/invoice.controller.ts` (baris 38) mengambil data tagihan langsung berdasarkan parameter URL tanpa memverifikasi apakah `invoice` tersebut milik pengguna yang sedang *login* (`req.user.organizationId`).
> 
> **Dampak Eksploitasi:**
> Pengguna terautentikasi dari Organisasi A dapat melihat dan mengunduh dokumen tagihan sensitif milik Organisasi B hanya dengan mengganti parameter `invoiceId`.
> 
> **Perbaikan yang Diterapkan oleh Quell:**
> Menambahkan klausa filter kepemilikan `organizationId: req.user.organizationId` ke dalam *query* Prisma ORM serta mengembalikan HTTP `404 Not Found` jika data tidak cocok.
> 
> **Perubahan Kode (`src/controllers/invoice.controller.ts`):**
> * **Sebelum (Rentan):**
>   `const invoice = await prisma.invoice.findUnique({ where: { id: req.params.invoiceId } });`
> * **Sesudah (Diamankan oleh Quell):**
>   `const invoice = await prisma.invoice.findFirst({ where: { id: req.params.invoiceId, organizationId: req.user.organizationId } });`

---

## 6. Arsitektur Teknis & Tech Stack

Arsitektur dipilih agar memiliki biaya operasional server yang rendah, *scalable*, dan dapat dibangun dengan cepat:

* **Frontend & Dashboard:** Next.js (App Router), Tailwind CSS, shadcn/ui.
* **Backend & API Orchestrator:** Golang atau Python (FastAPI) untuk pemrosesan *webhook* dan orkestrasi agen AI.
* **Task Queue & Background Workers:** Redis + BullMQ / Asynq (untuk mengatur antrean pemindaian kode secara *asynchronous*).
* **Database Utama & Vector Store:** PostgreSQL dengan ekstensi `pgvector` (menghemat biaya infrastruktur karena menyatukan data relasional dan *vector embedding* di satu database, seperti Supabase atau Neon).
* **Code Parsing & Static Analysis:** `Tree-sitter` (untuk pembuatan AST multi-bahasa) + `Semgrep OSS Engine` (sebagai pemindai deterministik tahap awal).
* **AI Inference & Tiered Routing:**
  * *Model Filter/Triage (Murah & Cepat):* Gemini 2.5 Flash / Claude Haiku / DeepSeek V3 untuk menyaring *false positive*.
  * *Model Patching (Akurasi Tinggi):* Claude 3.5/3.7 Sonnet atau Gemini 2.5 Pro khusus untuk menulis *diff patch* kode yang presisi.
* **Sandbox Execution:** Docker kontainer dengan batas memori ketat dan masa hidup singkat (*ephemeral*) yang langsung dihapus (`rm -rf`) begitu analisis selesai.

---

## 7. Keamanan Data & Non-Functional Requirements

Karena Quell adalah produk keamanan, kepercayaan pelanggan (*trust*) adalah segalanya:

1. **Zero Source Code Retention:** Quell **tidak menyimpan** *source code* mentah pelanggan secara permanen di database. Kode hanya di-*clone* ke dalam memori sementara (*ephemeral container*) selama proses pemindaian berlangsung ($< 60$ detik), lalu langsung dihancurkan. Database hanya menyimpan metadata temuan (nama file, nomor baris, jenis celah, dan potongan *patch*).
2. **No AI Training Policy:** Menggunakan API LLM tingkat *Enterprise/Commercial* yang menjamin *zero data retention* dan memastikan kode klien tidak pernah digunakan untuk melatih model AI publik.
3. **Target Performa (SLA):**
   * Waktu analisis *incremental push* (perubahan $\le 10$ file): $< 45$ detik.
   * Waktu pemindaian penuh repositori awal ($\le 50.000$ baris kode): $< 3$ menit.

---

## 8. Strategi Monetisasi, Pricing & Unit Economics

### 8.1 Tabel Paket Langganan (Subscription Tiers)

| Fitur / Kuota | **Starter (Indie)** | **Growth (Startup / Agency)** | **Scale (Enterprise)** |
| :--- | :--- | :--- | :--- |
| **Harga Bulanan** | **Rp 450.000** ($29 / bln) | **Rp 1.500.000** ($99 / bln) | **Rp 6.000.000** ($399 / bln) |
| **Kapasitas Repositori** | Maksimal 3 Repositori Privat | Maksimal 15 Repositori Privat | Unlimited Repositori |
| **Kuota Auto-PR / Bulan** | 20 Auto-Fix PR | Unlimited Auto-Fix PR | Unlimited Auto-Fix PR |
| **Frekuensi Pemindaian** | Setiap *Pull Request* & Mingguan | *Real-time* di setiap `git push` | *Real-time* + *Custom CI/CD Gate* |
| **Bahasa Pemrograman** | JS/TS, Python, Go, PHP | Semua Bahasa Utama + IaC | Semua Bahasa + *Custom Rules* |
| **Laporan Kepatuhan** | Ringkasan Web | Export PDF Standar | Laporan Audit ISO 27001 / UU PDP |

### 8.2 Perhitungan Unit Economics & Margin Keuntungan

Dengan strategi **Hybrid Scanning** (menyaring kode menggunakan AST lokal yang gratis terlebih dahulu, lalu hanya mengirimkan potongan fungsi yang mencurigakan ke API LLM), biaya per pelanggan dapat ditekan sangat rendah:

* **Rata-rata Pemakaian Token AI per Pelanggan (Tier Growth):**
  * Asumsi 15 repositori melakukan 200 *push* per bulan.
  * Pemindaian lokal (`Tree-sitter` + `Semgrep`) menyaring $90\%$ kode yang aman tanpa memanggil LLM.
  * Hanya sekitar 50 potongan kode mencurigakan per bulan yang dikirim ke API LLM ($\approx 500.000$ *input tokens* dan $100.000$ *output tokens*).
  * Estimasi biaya API LLM per pelanggan per bulan: $\approx \$3.50$ (Rp 55.000).
* **Biaya Infrastruktur Server & Database (Terbagi/Shared):** $\approx \$2.50$ (Rp 40.000) per pelanggan aktif.
* **Total Harga Pokok Penjualan (COGS) per Pelanggan Growth:**

$$\text{COGS} = \text{Rp } 55.000 + \text{Rp } 40.000 = \text{Rp } 95.000 \text{ / bulan}$$

* **Perhitungan Gross Margin (Margin Kotor):**

$$\text{Gross Margin} = \left( \frac{\text{Revenue} - \text{COGS}}{\text{Revenue}} \right) \times 100\%$$

$$\text{Gross Margin (Tier Growth)} = \left( \frac{1.500.000 - 95.000}{1.500.000} \right) \times 100\% = 93.6\%$$

*(Catatan: Bahkan setelah dikurangi potongan biaya Payment Gateway sebesar $2.9\%$, margin keuntungan bersih per pelanggan masih berada di kisaran $\approx 90\%$).*

### 8.3 Target Proyeksi Keuntungan Tahun Pertama

| Milestone Waktu | Target Pelanggan Berbayar | Breakdown Pelanggan | Estimasi MRR (Pendapatan Bulanan) | Estimasi Biaya Operasional | Profit Bersih Bulanan |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Bulan ke-3 (Launch)** | 15 Pelanggan | 10 Starter, 5 Growth | Rp 12.000.000 | Rp 1.800.000 | **Rp 10.200.000** |
| **Bulan ke-6** | 50 Pelanggan | 30 Starter, 18 Growth, 2 Scale | Rp 52.500.000 | Rp 6.500.000 | **Rp 46.000.000** |
| **Bulan ke-12** | 140 Pelanggan | 80 Starter, 50 Growth, 10 Scale | Rp 171.000.000 | Rp 19.000.000 | **Rp 152.000.000** |

---

## 9. Strategi Go-To-Market (GTM) & Akuisisi Pelanggan

Untuk mendapatkan pelanggan berbayar pertama tanpa membakar uang di iklan berbayar yang mahal, Quell menggunakan pendekatan **Product-Led Growth (PLG)**:

1. **Free "Instant Repo Security Scorecard" (Lead Magnet):**
   * Di halaman depan `quell.sh`, sediakan kolom input tempat *developer* bisa menempelkan URL repositori publik atau melakukan *1-click scan* pada 1 repositori privat mereka secara gratis.
   * Tampilkan hasilnya: *"Ditemukan 3 celah keamanan kritis di repositori Anda."*
   * Di bawah setiap temuan, tampilkan kode perbaikan yang sebagian di-*blur* dengan tombol CTA: **"Buka Kunci & Kirim Auto-Fix PR Sekarang ($29/bln)"**.
2. **Program Kemitraan Software House (B2B Channel):**
   * Tawarkan komisi afiliasi berulang (*recurring commission* $20\%$) atau paket *White-Label PDF Report* kepada pemilik *software house* lokal maupun global agar mereka memasang Quell di seluruh proyek klien mereka.
3. **Peluncuran di Komunitas Developer & Indie Hacker:**
   * Rilis `quell-cli` versi *open-source* terbatas di GitHub, Product Hunt, Hacker News (*Show HN*), dan komunitas lokal untuk membangun reputasi dan *backlink* organik.

---

## 10. Metrik Keberhasilan (Key Performance Indicators)

* **North Star Metric:** Jumlah *Security Pull Request* yang berhasil di-*merge* oleh pengguna per minggu (*Weekly Merged Security PRs*).
* **Time-to-First-Value (TTFV):** Rata-rata waktu dari pengguna menekan tombol *Sign Up* hingga PR perbaikan pertama muncul di GitHub mereka (Target: $< 3$ menit).
* **PR Acceptance Rate:** Persentase PR yang dibuat oleh `quell-bot` yang disetujui (*merged*) dibanding yang ditolak (*closed*) oleh *developer* (Target: $\ge 70\%$).
* **Monthly Churn Rate:** Persentase pelanggan yang berhenti berlangganan setiap bulan (Target B2B DevSecOps: $< 4\%$).

---

## 11. Roadmap Eksekusi MVP (8 Minggu)

* **Minggu 1–2 (Core Engine & Proof of Concept):**
  * Membangun skrip pemotong kode berbasis *Tree-sitter* dan merancang *system prompt* AI yang mampu mendeteksi 5 celah utama (SQLi, IDOR, XSS, SSRF, Hardcoded Secrets) pada proyek Node.js/TypeScript serta menghasilkan output berformat `git diff`.
* **Minggu 3–4 (GitHub App & Bot Automation):**
  * Membangun *backend webhook listener*, integrasi GitHub App (`quell-bot`), dan alur pembuatan *branch* serta *Pull Request* otomatis.
* **Minggu 5–6 (Web Dashboard & Billing):**
  * Membangun antarmuka pengguna dengan Next.js untuk *onboarding* repositori, melihat riwayat pemindaian, dan mengintegrasikan *payment gateway* untuk sistem langganan.
* **Minggu 7 (Closed Beta & Fine-Tuning):**
  * Menguji Quell pada 10–15 repositori milik teman *developer* atau proyek nyata untuk menekan angka *false positive* dan menyempurnakan kualitas kode *patch*.
* **Minggu 8 (Public Launch & Monetization):**
  * Meluncurkan halaman utama beserta fitur *Free Security Scorecard* dan membuka pendaftaran paket berbayar.