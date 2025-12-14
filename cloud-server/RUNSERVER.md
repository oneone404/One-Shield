✅ BƯỚC 1 — BẬT DATABASE (Docker)

📌 Không có DB → API chết ngay

cd cloud-server
docker compose up -d postgres

🔍 Check nhanh:

docker ps

✔ Phải thấy:

oneshield-db postgres Up (healthy)

✅ BƯỚC 2 — CHẠY API SERVER (Rust)

📌 API chỉ chạy được khi DB đã sống

cargo run --release

🔍 Dấu hiệu đúng:

Server starting...
Listening on 0.0.0.0:8080

🔍 Test local:

Invoke-RestMethod http://localhost:8080/health

✔ Trả về status: healthy

✅ BƯỚC 3 — NỐI INTERNET (Cloudflare Tunnel)

📌 Tunnel chỉ là “dây mạng”, không tạo server

cloudflared tunnel run oneshield-api

🔍 Dấu hiệu đúng:

Registered tunnel connection

🔍 Test public:

Invoke-RestMethod https://api.accone.vn/health
