# One-Shield Cloud Server

Central management server for One-Shield EDR agents.

## 🚀 Quick Start

### 1. Start Database (Docker)

```bash
# Start PostgreSQL and Adminer
docker-compose up -d

# Check status
docker-compose ps
```

**Services:**
- **PostgreSQL**: `localhost:5432` (user: `oneshield`, pass: `oneshield`)
- **Adminer UI**: `http://localhost:8081`

### 2. Setup Environment

```bash
# Copy example config
cp .env.example .env

# Or create manually:
cat > .env << 'EOF'
DATABASE_URL=postgres://oneshield:oneshield@localhost:5432/oneshield
PORT=8080
ENVIRONMENT=development
JWT_SECRET=dev-jwt-secret-key-change-in-production-123456
JWT_EXPIRATION_HOURS=24
AGENT_SECRET=dev-agent-secret-change-in-production-789012
EOF
```

### 3. Run Server

```bash
cargo run
```

Server starts at: `http://localhost:8080`

---

## 🔐 Default Credentials

| Service | Username/Email | Password |
|---------|---------------|----------|
| Database | `oneshield` | `oneshield` |
| Admin User | `admin@oneshield.local` | `admin123` |

---

## 📡 API Endpoints

### Public (No Auth)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/v1/auth/login` | User login |
| POST | `/api/v1/auth/register` | Register org + admin |

### Agent (Token Auth)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/agent/register` | Register new agent |
| POST | `/api/v1/agent/heartbeat` | Send heartbeat |
| POST | `/api/v1/agent/sync/baseline` | Sync baseline |
| POST | `/api/v1/agent/sync/incidents` | Sync incidents |
| GET | `/api/v1/agent/policy` | Get active policy |

### Management (JWT Auth)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/endpoints` | List endpoints |
| GET | `/api/v1/endpoints/:id` | Get endpoint |
| DELETE | `/api/v1/endpoints/:id` | Delete endpoint |
| GET | `/api/v1/incidents` | List incidents |
| GET | `/api/v1/incidents/:id` | Get incident |
| PUT | `/api/v1/incidents/:id/status` | Update status |
| GET | `/api/v1/policies` | List policies |
| POST | `/api/v1/policies` | Create policy |
| GET | `/api/v1/reports/executive` | Executive report |
| GET | `/api/v1/reports/compliance` | Compliance report |
| GET | `/api/v1/organization` | Get org details |
| GET | `/api/v1/organization/users` | List users |

---

## 🧪 Test API

### Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@oneshield.local","password":"admin123"}'
```

### Use Token
```bash
TOKEN="<token-from-login>"
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/endpoints
```

### Register Agent
```bash
curl -X POST http://localhost:8080/api/v1/agent/register \
  -H "Content-Type: application/json" \
  -d '{
    "hostname":"my-workstation",
    "os_type":"Windows",
    "os_version":"10.0.19045",
    "agent_version":"2.3.0",
    "registration_key":"dev-agent-secret-change-in-production-789012"
  }'
```

---

## 🐳 Docker Commands

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f postgres

# Stop services
docker-compose down

# Reset database
docker-compose down -v
docker-compose up -d
```

---

## 📁 Project Structure

```
cloud-server/
├── Cargo.toml
├── docker-compose.yml      # PostgreSQL + Adminer
├── init.sql                # Database schema
├── .env.example
└── src/
    ├── main.rs             # Entry point + router
    ├── config.rs           # Configuration
    ├── db.rs               # Database connection
    ├── error.rs            # Error handling
    ├── middleware/
    │   └── auth.rs         # JWT + Agent auth
    ├── models/             # Data models
    └── handlers/           # API handlers
```

---

## 🔧 Development

```bash
# Check code
cargo check

# Run with auto-reload (requires cargo-watch)
cargo install cargo-watch
cargo watch -x run

# Run tests
cargo test
```
