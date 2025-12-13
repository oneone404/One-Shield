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

# Build and run
cargo run --release

# Server starts at http://localhost:8080
```

### Option B: Production (Background)

```powershell
cd cloud-server

# Build release binary
cargo build --release

# Run in background (Windows)
Start-Process -NoNewWindow -FilePath ".\target\release\oneshield-cloud.exe"

# Or using PM2 (cross-platform)
npm install -g pm2
pm2 start "cargo run --release" --name oneshield-api
pm2 save
```

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
Write-Host "✅ Dashboard deployed!"
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

```powershell
# Foreground
cloudflared tunnel run oneshield-api

# Background (Windows Service)
cloudflared service install
cloudflared service start
```

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

### Update Deployment

```powershell
# Pull latest code
git pull origin main

# Rebuild API
cd cloud-server
cargo build --release

# Rebuild & deploy dashboard
cd dashboard
npm run build
cmd /c "npx wrangler pages deploy dist --project-name=oneshield-dashboard --commit-dirty=true --commit-message=Update"

# Restart API server
# (depends on your deployment method)
```

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

```powershell
# 1. Start database
cd cloud-server
docker compose up -d postgres adminer

# 2. Start API
cargo run --release

# 3. (New terminal) Start tunnel
cloudflared tunnel run oneshield-api

# 4. Deploy dashboard (if changed)
cd dashboard
npm run build
cmd /c "npx wrangler pages deploy dist --project-name=oneshield-dashboard --commit-dirty=true"

# Done! 🎉
# - Dashboard: https://dashboard.accone.vn
# - API: https://api.accone.vn
```
