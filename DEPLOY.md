# One-Shield Deployment Guide

> **Complete guide to deploy One-Shield system to production**
> **Last Updated**: 2025-12-13

---

## 📋 Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Infrastructure Setup](#infrastructure-setup)
4. [Database Setup](#database-setup)
5. [API Server Deployment](#api-server-deployment)
6. [Dashboard Deployment](#dashboard-deployment)
7. [Cloudflare Configuration](#cloudflare-configuration)
8. [Desktop App Build](#desktop-app-build)
9. [Maintenance Commands](#maintenance-commands)
10. [Troubleshooting](#troubleshooting)

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      INTERNET                               │
└─────────────────────────┬───────────────────────────────────┘
                          │
                    Cloudflare
                    (DNS + Proxy + SSL)
                          │
         ┌────────────────┼────────────────┐
         │                │                │
         ▼                ▼                ▼
   dashboard.        api.accone.vn    accone.vn
   accone.vn              │               │
         │                │               │
   Cloudflare        Cloudflare      Cloudflare
   Pages             Tunnel           (static)
         │                │
         ▼                ▼
   Static Files     Local Server
   (dist/)          (cargo run)
                          │
                    ┌─────┴─────┐
                    │           │
                    ▼           ▼
              PostgreSQL    cloud-server
              (Docker)      (Rust/Axum)
                              :8080
```

### Components

| Component | Technology | Port | Hosting |
|-----------|------------|------|---------|
| **Dashboard** | React + Vite | - | Cloudflare Pages |
| **API Server** | Rust + Axum | 8080 | Local + Cloudflare Tunnel |
| **Database** | PostgreSQL 16 | 5432 | Docker |
| **DB Admin** | Adminer | 8081 | Docker |
| **Desktop App** | Tauri + React | - | Installer |

---

## 📦 Prerequisites

### Required Software

```powershell
# Check versions
node --version    # >= 18.x
npm --version     # >= 9.x
cargo --version   # >= 1.75
docker --version  # >= 24.x
```

### Required Accounts

- **Cloudflare** account with domain configured
- **GitHub** account (for repo access)

### Environment Variables

Create `.env` file in `cloud-server/`:

```env
# Database
DATABASE_URL=postgres://oneshield:oneshield@localhost:5432/oneshield

# JWT Secret (generate with: openssl rand -hex 32)
JWT_SECRET=your-super-secret-key-here-at-least-32-chars

# Server
PORT=8080
RUST_LOG=info
```

---

## 🗄️ Infrastructure Setup

### 1. Clone Repository

```powershell
git clone https://github.com/oneone404/One-Shield.git
cd One-Shield
```

### 2. Start Docker Services

```powershell
cd cloud-server

# Start PostgreSQL + Adminer
docker compose up -d postgres adminer

# Verify containers running
docker ps
```

**Expected output:**
```
NAMES               IMAGE                STATUS
oneshield-db        postgres:16-alpine   Up (healthy)
oneshield-adminer   adminer:latest       Up
```

---

## 🐘 Database Setup

### Initial Setup (First Time Only)

Database is auto-initialized from `init.sql` when container starts.

### Manual Migration (If Needed)

```powershell
# Connect to database
docker exec -it oneshield-db psql -U oneshield -d oneshield

# Run SQL commands
\dt  # List tables
\q   # Quit
```

### Add Missing Columns (If Error)

```sql
-- Run if you see "column does not exist" errors
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW();
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS tier VARCHAR(50) DEFAULT 'organization';
```

### Database Access UI

- **URL**: http://localhost:8081
- **System**: PostgreSQL
- **Server**: postgres
- **Username**: oneshield
- **Password**: oneshield
- **Database**: oneshield

---

## 🦀 API Server Deployment

### Option A: Development (Local)

```powershell
cd cloud-server

# Build and run (dev)
cargo run --release

# Server starts at http://localhost:8080
```

### Option B: Production (Recommended)

```powershell
cd cloud-server

# 1. Build release binary FIRST
cargo build --release

# 2. Run the compiled binary (NOT cargo run)
.\target\release\oneshield-cloud.exe

# 3. Or use PM2 for process management
npm install -g pm2
pm2 start .\target\release\oneshield-cloud.exe --name oneshield-api
pm2 save
pm2 startup  # Auto-start on reboot
```

> ⚠️ **IMPORTANT**: In production, ALWAYS run the compiled binary, NOT `cargo run`.
> `cargo run --release` rebuilds on every restart = slow + risk.

### Health Check

```powershell
# Test API
Invoke-RestMethod -Uri "http://localhost:8080/health"

# Expected:
# status    : healthy
# version   : 0.1.0
# timestamp : ...
```

---

## 🌐 Dashboard Deployment

### Build Dashboard

```powershell
cd cloud-server/dashboard

# Install dependencies
npm install

# Build production
npm run build

# Output: dist/ folder
```

### Deploy to Cloudflare Pages

```powershell
cd cloud-server/dashboard

# Login to Cloudflare (first time)
cmd /c "npx wrangler login"

# Deploy
cmd /c "npx wrangler pages deploy dist --project-name=oneshield-dashboard --commit-dirty=true --commit-message=Deploy"
```

> ⚠️ **WARNING - Windows PowerShell UTF-8 Issue:**
> - ALWAYS use ASCII-only `--commit-message`
> - ❌ NO emoji, NO tiếng Việt, NO special characters
> - ✅ Good: `--commit-message=Deploy` or `--commit-message=UpdateV2`
> - ❌ Bad: `--commit-message="Deploy 🚀"` or `--commit-message="Cập nhật"`

**Expected output:**
```
✨ Success! Uploaded X files
🌎 Deploying...
✨ Deployment complete! https://xxx.oneshield-dashboard.pages.dev
```

### Quick Deploy Script

Create `deploy-dashboard.ps1`:

```powershell
#!/usr/bin/env pwsh
Set-Location "$PSScriptRoot/cloud-server/dashboard"
npm run build
cmd /c "npx wrangler pages deploy dist --project-name=oneshield-dashboard --commit-dirty=true --commit-message=Deploy"
Write-Host "Dashboard deployed!"
```

---

## ☁️ Cloudflare Configuration

### DNS Records

| Type | Name | Content | Proxy |
|------|------|---------|-------|
| CNAME | dashboard | oneshield-dashboard.pages.dev | ✅ Proxied |
| CNAME | api | <tunnel-id>.cfargotunnel.com | ✅ Proxied |

### Cloudflare Tunnel Setup

#### 1. Install cloudflared

```powershell
# Windows
winget install Cloudflare.cloudflared

# Or download from:
# https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation
```

#### 2. Login

```powershell
cloudflared tunnel login
```

#### 3. Create Tunnel

```powershell
cloudflared tunnel create oneshield-api

# Note the Tunnel ID from output
```

#### 4. Configure Tunnel

Create `~/.cloudflared/config.yml`:

```yaml
tunnel: <your-tunnel-id>
credentials-file: C:\Users\<username>\.cloudflared\<tunnel-id>.json

ingress:
  - hostname: api.accone.vn
    service: http://localhost:8080
  - service: http_status:404
```

#### 5. Add DNS Route

```powershell
cloudflared tunnel route dns oneshield-api api.accone.vn
```

#### 6. Run Tunnel

**Development (manual):**
```powershell
cloudflared tunnel run oneshield-api
```

**Production (Windows Service) - RECOMMENDED:**
```powershell
# Install as Windows Service (run once)
cloudflared service install

# Start service
cloudflared service start

# Check status
cloudflared service status
```

> ⚠️ **PRODUCTION RULE:**
> - ✅ ALWAYS use `cloudflared service install` + `service start`
> - ❌ DO NOT use `cloudflared tunnel run` manually
> - Reason: Service auto-restarts after reboot, manual run = API dies on reboot

---

## 🖥️ Desktop App Build

### Development

```powershell
cd core-service

# Run with dev server
cargo tauri dev
```

### Production Build

```powershell
cd core-service

# Build installer
cargo tauri build

# Output: target/release/bundle/
# - msi/OneShield_x.x.x_x64.msi
# - nsis/OneShield_x.x.x_x64-setup.exe
```

### Distribution

Upload installers to:
- GitHub Releases
- Your website download page
- S3/Cloudflare R2

---

## 🔧 Maintenance Commands

### Daily Operations

```powershell
# Check all services
docker ps
Invoke-RestMethod -Uri "http://localhost:8080/health"

# View API logs
# (if running with cargo run, logs appear in terminal)

# View database
docker logs oneshield-db
```

### Restart Services

```powershell
# Restart database
docker compose restart postgres

# Restart API (if using PM2)
pm2 restart oneshield-api

# Restart Cloudflare Tunnel
cloudflared service restart
```

---

## 🔄 Updating System (After Initial Deployment)

### Case 1: Update Dashboard Only (UI changes)

> ✅ NO restart needed for API, Database, or Tunnel

```powershell
cd cloud-server/dashboard

git pull origin main
npm install        # only if dependencies changed
npm run build

cmd /c "npx wrangler pages deploy dist --project-name=oneshield-dashboard --commit-dirty=true --commit-message=Update"
```

**Why no restart?** Dashboard is static files on Cloudflare Pages - completely independent.

---

### Case 2: Update Backend (API / Logic)

> ⚠️ Requires API restart, but NOT tunnel or database

```powershell
cd cloud-server

git pull origin main
cargo build --release

# Restart API
pm2 restart oneshield-api

# Verify
Invoke-RestMethod -Uri "http://localhost:8080/health"
```

**Tunnel stays connected** - as long as port 8080 doesn't change.

---

### Case 3: Update Database Schema

> ⚠️ ALWAYS backup before schema changes

```powershell
# Backup first
docker exec oneshield-db pg_dump -U oneshield oneshield > backup_before_migration.sql

# Run migration
docker exec -it oneshield-db psql -U oneshield -d oneshield

# Example: Add column
ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS new_field VARCHAR(255);

# Exit psql
\q
```

**Usually NO restart needed** unless connection pool issues.

---

### Case 4: Server Reboot / Crash Recovery

> Full recovery after server restart or crash

```powershell
# 1. Start Database
cd cloud-server
docker compose up -d postgres

# 2. Start API (PM2 auto-resurrects if configured)
pm2 resurrect
# OR if PM2 not configured:
pm2 start .\target\release\oneshield-cloud.exe --name oneshield-api

# 3. Start Tunnel (if installed as service, auto-starts)
cloudflared service start

# 4. Verify everything
docker ps                                              # DB running
Invoke-RestMethod -Uri "http://localhost:8080/health"  # API running
Invoke-RestMethod -Uri "https://api.accone.vn/health"  # Tunnel working
```

---

### Quick Reference: What to Restart?

| Change Type | Database | API | Tunnel | Dashboard |
|-------------|----------|-----|--------|-----------|
| UI only | ❌ | ❌ | ❌ | ✅ Deploy |
| API logic | ❌ | ✅ Restart | ❌ | ❌ |
| DB schema | ⚠️ Maybe | ❌ | ❌ | ❌ |
| Server reboot | ✅ Start | ✅ Start | ✅ Start | ❌ |
| Tunnel config | ❌ | ❌ | ✅ Restart | ❌ |


### Database Backup

```powershell
# Backup
docker exec oneshield-db pg_dump -U oneshield oneshield > backup_$(Get-Date -Format "yyyyMMdd").sql

# Restore
docker exec -i oneshield-db psql -U oneshield oneshield < backup_20241213.sql
```

### Cleanup Test Data

```powershell
docker exec oneshield-db psql -U oneshield -d oneshield -c "
DELETE FROM endpoints WHERE hostname LIKE 'Test%';
DELETE FROM organization_tokens WHERE name LIKE 'Test%';
DELETE FROM users WHERE email LIKE 'test-%@example.com';
DELETE FROM organizations WHERE name LIKE 'Test%' OR name LIKE 'Personal - test-%';
"
```

---

## 🐛 Troubleshooting

### API Server Won't Start

```powershell
# Check port in use
netstat -ano | findstr :8080

# Check database connection
docker exec oneshield-db pg_isready -U oneshield

# Check logs
cargo run 2>&1 | Out-File debug.log
```

### Database Connection Failed

```powershell
# Verify Docker running
docker ps

# Restart PostgreSQL
docker compose restart postgres

# Check DATABASE_URL in .env
```

### Cloudflare Tunnel Not Working

```powershell
# Check tunnel status
cloudflared tunnel info oneshield-api

# Test local API first
Invoke-RestMethod -Uri "http://localhost:8080/health"

# Restart tunnel
cloudflared service restart
```

### Dashboard Shows Old Version

```powershell
# Clear Cloudflare cache
# Go to: Cloudflare Dashboard > Caching > Purge Everything

# Or redeploy
cd cloud-server/dashboard
npm run build
cmd /c "npx wrangler pages deploy dist --project-name=oneshield-dashboard --commit-dirty=true"
```

### 502 Bad Gateway

- API server not running → Start with `cargo run --release`
- Cloudflare Tunnel disconnected → Run `cloudflared tunnel run`
- Port mismatch → Check config.yml points to :8080

---

## 📊 Quick Reference

### URLs

| Service | Local | Production |
|---------|-------|------------|
| API | http://localhost:8080 | https://api.accone.vn |
| Dashboard | http://localhost:5173 | https://dashboard.accone.vn |
| DB Admin | http://localhost:8081 | (local only) |

### Ports

| Port | Service |
|------|---------|
| 5432 | PostgreSQL |
| 8080 | API Server |
| 8081 | Adminer |
| 5173 | Vite Dev Server |
| 3000 | Dashboard Docker |

### Important Files

```
cloud-server/
├── .env                    # Environment variables
├── docker-compose.yml      # Docker services
├── init.sql               # Database schema
├── src/                   # Rust source
└── dashboard/
    ├── dist/              # Built static files
    └── nginx.conf         # Nginx config

~/.cloudflared/
├── config.yml             # Tunnel config
└── <tunnel-id>.json       # Tunnel credentials
```

---

## 🚀 Quick Start (TL;DR)

### Development

```powershell
# 1. Start database
cd cloud-server
docker compose up -d postgres adminer

# 2. Start API (dev)
cargo run --release

# 3. (New terminal) Start tunnel (dev)
cloudflared tunnel run oneshield-api

# 4. Deploy dashboard (if changed)
cd dashboard
npm run build
cmd /c "npx wrangler pages deploy dist --project-name=oneshield-dashboard --commit-dirty=true --commit-message=Deploy"

# Done! 🎉
```

### Production

```powershell
# 1. Database
cd cloud-server
docker compose up -d postgres

# 2. Build & start API (compiled binary)
cargo build --release
pm2 start .\target\release\oneshield-cloud.exe --name oneshield-api
pm2 save

# 3. Tunnel as service
cloudflared service install
cloudflared service start

# 4. Dashboard on Cloudflare Pages (already deployed)

# URLs:
# - Dashboard: https://dashboard.accone.vn
# - API: https://api.accone.vn
```

---

## 🔐 Security Notes (Production)

> **CRITICAL for production deployment:**

### Environment & Secrets

- ❌ **NEVER** commit `.env` to Git (already in `.gitignore`)
- 🔄 **ROTATE** `JWT_SECRET` before public launch
- 🔑 Generate strong secret: `openssl rand -hex 32`

### Network Exposure

| Port | Should be public? | Notes |
|------|------------------|-------|
| 8080 | ❌ Only via Tunnel | Cloudflare Tunnel handles SSL |
| 5432 | ❌ Never | PostgreSQL - localhost only |
| 8081 | ❌ Never | Adminer - localhost only |

### Cloudflare Tunnel

- ✅ Exposes ONLY port 8080 (API)
- ✅ Handles SSL/TLS automatically
- ✅ DDoS protection included
- ✅ No firewall rules needed on server

### Database

- ✅ PostgreSQL bound to localhost (Docker internal)
- ✅ Credentials in `.env` only
- 🔄 Change default password for production:

```yaml
# docker-compose.yml
environment:
  POSTGRES_PASSWORD: ${DB_PASSWORD}  # Use env var
```

### Checklist Before Public Launch

- [ ] Change JWT_SECRET to new random value
- [ ] Change database password
- [ ] Remove Adminer container (or restrict access)
- [ ] Enable Cloudflare WAF rules
- [ ] Test rate limiting
- [ ] Verify HTTPS only (no HTTP)
