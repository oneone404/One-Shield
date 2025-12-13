# Phase 12: Enterprise Enrollment & Multi-Tenant Scale

> **Mục tiêu**: Implement Org Enrollment Token system cho multi-tenant SaaS EDR
> **Effort**: ~4-6 giờ
> **Priority**: 🔴 HIGH (Block multi-org deployment)

---

## 📋 Tổng quan

### Vấn đề hiện tại
- ❌ Agent hardcode `registration_key`
- ❌ Tất cả agent register vào Default Org
- ❌ Không scale multi-org
- ❌ Không revoke được agent

### Giải pháp
- ✅ Org tạo Enrollment Token
- ✅ Agent dùng token để register vào đúng Org
- ✅ Token có thể expire/revoke
- ✅ Scale vô hạn orgs

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ENROLLMENT FLOW                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────┐    1. Create Token    ┌───────────────────┐     │
│   │  Admin   │ ───────────────────► │    Dashboard      │     │
│   │  User    │                      │ (Settings page)   │     │
│   └──────────┘                      └─────────┬─────────┘     │
│                                               │                │
│                                     2. Generate Token          │
│                                               ▼                │
│                              ┌─────────────────────────┐       │
│                              │  organization_tokens    │       │
│                              │  - token: ORG_xxx       │       │
│                              │  - org_id: uuid         │       │
│                              │  - expires_at: optional │       │
│                              └─────────────────────────┘       │
│                                               │                │
│   ┌──────────┐    3. Copy Install URL         │                │
│   │  Admin   │ ◄──────────────────────────────┘                │
│   └────┬─────┘                                                 │
│        │ 4. Install Agent with Token                           │
│        ▼                                                       │
│   ┌─────────────────────────────────────────────────────┐      │
│   │  OneShield.exe --enroll-token=ORG_xxx               │      │
│   │                     OR                              │      │
│   │  https://api.accone.vn/install?token=ORG_xxx        │      │
│   └───────────────────────────┬─────────────────────────┘      │
│                               │                                │
│                     5. POST /agent/enroll                      │
│                               ▼                                │
│                  ┌─────────────────────────┐                   │
│                  │     Cloud Server        │                   │
│                  │  - Validate token       │                   │
│                  │  - Get org_id           │                   │
│                  │  - Register agent       │                   │
│                  │  - Return agent_token   │                   │
│                  └─────────────────────────┘                   │
│                               │                                │
│                     6. Save Identity                           │
│                               ▼                                │
│                  ┌─────────────────────────┐                   │
│                  │   agent_identity.json   │                   │
│                  │  - agent_id             │                   │
│                  │  - agent_token          │                   │
│                  │  - org_id               │                   │
│                  │  - hwid                 │                   │
│                  └─────────────────────────┘                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📦 12.1 Database Schema

### Task 12.1.1: Create `organization_tokens` table

**File**: `cloud-server/migrations/add_enrollment_tokens.sql`

```sql
-- Organization Enrollment Tokens
CREATE TABLE IF NOT EXISTS organization_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Token value (unique, random)
    token VARCHAR(255) NOT NULL UNIQUE,

    -- Friendly name for the token
    name VARCHAR(100) NOT NULL DEFAULT 'Default Token',

    -- Optional expiration
    expires_at TIMESTAMPTZ,

    -- Usage limits
    max_uses INT,                    -- NULL = unlimited
    uses_count INT DEFAULT 0,

    -- Audit
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

-- Indexes
CREATE INDEX idx_tokens_org ON organization_tokens(org_id);
CREATE INDEX idx_tokens_token ON organization_tokens(token);
CREATE INDEX idx_tokens_active ON organization_tokens(is_active, expires_at);
```

**Checklist**:
- [ ] 12.1.1 Create migration file
- [ ] 12.1.2 Add to init.sql
- [ ] 12.1.3 Create model in Rust

---

## 🔌 12.2 Backend API

### Task 12.2.1: Token Management APIs

**File**: `cloud-server/src/handlers/tokens.rs`

```rust
// Endpoints:
POST   /api/v1/tokens              // Create new token
GET    /api/v1/tokens              // List org tokens
GET    /api/v1/tokens/:id          // Get token details
DELETE /api/v1/tokens/:id          // Revoke token
```

**Request/Response**:

```rust
// Create Token Request
#[derive(Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    pub expires_in_days: Option<i64>,  // None = never expires
    pub max_uses: Option<i32>,         // None = unlimited
}

// Create Token Response
#[derive(Serialize)]
pub struct CreateTokenResponse {
    pub id: Uuid,
    pub token: String,                 // "ORG_xxxxxxxx"
    pub install_url: String,           // Full URL with token
    pub expires_at: Option<DateTime>,
}

// Token Info
#[derive(Serialize)]
pub struct TokenInfo {
    pub id: Uuid,
    pub name: String,
    pub token_preview: String,         // "ORG_xxx...xxx"
    pub uses_count: i32,
    pub max_uses: Option<i32>,
    pub expires_at: Option<DateTime>,
    pub is_active: bool,
    pub created_at: DateTime,
}
```

**Checklist**:
- [ ] 12.2.1 Create `CreateToken` handler
- [ ] 12.2.2 Create `ListTokens` handler
- [ ] 12.2.3 Create `RevokeToken` handler
- [ ] 12.2.4 Add routes to router

---

### Task 12.2.2: Agent Enrollment API

**File**: `cloud-server/src/handlers/agent.rs`

```rust
// New endpoint:
POST /api/v1/agent/enroll   // Public, no auth required
```

**Request/Response**:

```rust
// Enroll Request (từ Agent)
#[derive(Deserialize)]
pub struct EnrollAgentRequest {
    pub enrollment_token: String,      // "ORG_xxx"
    pub hwid: String,                  // Hardware ID
    pub hostname: String,
    pub os_type: String,
    pub os_version: String,
    pub agent_version: String,
}

// Enroll Response
#[derive(Serialize)]
pub struct EnrollAgentResponse {
    pub agent_id: Uuid,
    pub agent_token: String,           // For heartbeat auth
    pub org_id: Uuid,
    pub org_name: String,
}
```

**Handler Logic**:

```rust
pub async fn enroll(
    State(state): State<AppState>,
    Json(req): Json<EnrollAgentRequest>,
) -> AppResult<Json<EnrollAgentResponse>> {
    // 1. Validate enrollment token
    let token = validate_enrollment_token(&state.pool, &req.enrollment_token).await?;

    // 2. Check expiration
    if let Some(expires) = token.expires_at {
        if expires < Utc::now() {
            return Err(AppError::TokenExpired);
        }
    }

    // 3. Check max uses
    if let Some(max) = token.max_uses {
        if token.uses_count >= max {
            return Err(AppError::TokenMaxUsesReached);
        }
    }

    // 4. Check HWID uniqueness (prevent duplicate registration)
    if let Some(existing) = find_agent_by_hwid(&state.pool, &req.hwid).await? {
        // Re-enrollment: return existing credentials
        return Ok(Json(EnrollAgentResponse {
            agent_id: existing.id,
            agent_token: generate_new_token_for_agent(existing.id),
            org_id: existing.org_id,
            org_name: get_org_name(&state.pool, existing.org_id).await?,
        }));
    }

    // 5. Register new agent
    let agent_token = generate_agent_token();
    let endpoint = Endpoint::register(&state.pool, token.org_id, req, hash(&agent_token)).await?;

    // 6. Increment token usage
    increment_token_usage(&state.pool, token.id).await?;

    // 7. Get org name
    let org_name = get_org_name(&state.pool, token.org_id).await?;

    Ok(Json(EnrollAgentResponse {
        agent_id: endpoint.id,
        agent_token,
        org_id: token.org_id,
        org_name,
    }))
}
```

**Checklist**:
- [ ] 12.2.5 Create `EnrollAgentRequest` struct
- [ ] 12.2.6 Create `enroll` handler
- [ ] 12.2.7 Add `validate_enrollment_token` helper
- [ ] 12.2.8 Add HWID duplicate check
- [ ] 12.2.9 Add token usage increment (ATOMIC!)
- [ ] 12.2.10 Add route `/api/v1/agent/enroll`

---

### ⚠️ IMPORTANT: Race Condition Fix

**Vấn đề**: Nếu 100 máy cùng enroll đúng 1 tích tắc, code kiểm tra `uses_count < max_uses` có thể bị race condition.

```rust
// ❌ Code lỗi (Race Condition):
if token.uses_count < max {
    // 2 requests có thể cùng pass check này
    increment_token_usage(token.id).await?;  // Kết quả: 11 máy thay vì 10
}
```

**Giải pháp**: Dùng **Atomic SQL** với `UPDATE ... WHERE ... RETURNING`:

```sql
-- ✅ Atomic increment với condition
UPDATE organization_tokens
SET uses_count = uses_count + 1
WHERE id = $1
  AND (max_uses IS NULL OR uses_count < max_uses)
  AND is_active = true
  AND (expires_at IS NULL OR expires_at > NOW())
RETURNING id;

-- Nếu RETURNING rỗng → Token đã hết lượt hoặc expired
```

**Rust implementation**:

```rust
/// Atomic token usage increment - Race-condition safe
async fn try_use_token(pool: &PgPool, token_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE organization_tokens
        SET uses_count = uses_count + 1
        WHERE id = $1
          AND (max_uses IS NULL OR uses_count < max_uses)
          AND is_active = true
          AND (expires_at IS NULL OR expires_at > NOW())
        RETURNING id
        "#
    )
    .bind(token_id)
    .fetch_optional(pool)
    .await?;

    Ok(result.is_some())
}

// Usage in enroll handler:
pub async fn enroll(...) -> AppResult<Json<EnrollAgentResponse>> {
    // 1. Lookup token (no increment yet)
    let token = get_token_by_value(&state.pool, &req.enrollment_token).await?
        .ok_or(AppError::Unauthorized)?;

    // 2. Atomic: Try to use the token
    if !try_use_token(&state.pool, token.id).await? {
        // Token expired, revoked, or max uses reached
        return Err(AppError::TokenExhausted);
    }

    // 3. Now safe to register agent
    let endpoint = Endpoint::register(&state.pool, token.org_id, req).await?;

    // ... rest of handler
}
```

**Lợi ích**:
- ✅ 100% race-condition safe
- ✅ Một câu SQL query duy nhất
- ✅ Check tất cả conditions cùng lúc (max_uses, active, expires_at)
- ✅ Nếu fail → Rollback tự động (không có agent được tạo)

---

## 🖥️ 12.3 Agent Changes

### Task 12.3.1: CLI Argument for Enrollment Token

**File**: `core-service/src/main.rs`

```rust
use clap::Parser;

#[derive(Parser)]
struct Args {
    /// Enrollment token from organization (ORG_xxx)
    #[arg(long)]
    enroll_token: Option<String>,
}

fn main() {
    let args = Args::parse();

    // Pass to cloud sync
    if let Some(token) = args.enroll_token {
        std::env::set_var("ENROLLMENT_TOKEN", token);
    }

    // ... rest of app
}
```

**Checklist**:
- [ ] 12.3.1 Add `clap` to Cargo.toml
- [ ] 12.3.2 Parse CLI args
- [ ] 12.3.3 Pass token to cloud sync

---

### Task 12.3.2: Update Cloud Sync to use Enrollment

**File**: `core-service/src/logic/cloud_sync/sync.rs`

```rust
async fn register_with_enrollment(
    client: &mut CloudClient,
    enrollment_token: &str,
    hwid: &str,
) -> Result<EnrollResponse, CloudError> {
    let url = format!("{}/api/v1/agent/enroll", client.config.server_url);

    let request = EnrollAgentRequest {
        enrollment_token: enrollment_token.to_string(),
        hwid: hwid.to_string(),
        hostname: get_hostname(),
        os_type: "Windows".to_string(),
        os_version: get_os_version(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    // POST to enroll endpoint
    let response = client.http_client
        .post(&url)
        .json(&request)
        .send()
        .await?;

    // ... handle response
}
```

**Updated Flow**:

```rust
// In start_sync_loop:

// 1. Check for existing identity
let identity_state = identity_manager.initialize()?;

match identity_state {
    IdentityState::Loaded(identity) => {
        // Use existing identity
        client.set_token(&identity.agent_token);
    }
    IdentityState::NeedsRegistration { hwid } => {
        // Check for enrollment token
        let enrollment_token = std::env::var("ENROLLMENT_TOKEN")
            .or_else(|_| read_enrollment_token_from_file())
            .map_err(|_| "No enrollment token provided")?;

        // Enroll with token
        let response = register_with_enrollment(&mut client, &enrollment_token, &hwid).await?;

        // Save identity
        identity_manager.save_identity(
            response.agent_id,
            response.agent_token,
            response.org_id,
            &client.config.server_url,
        )?;
    }
    IdentityState::Invalid { .. } => {
        // Same as NeedsRegistration
    }
}
```

**Checklist**:
- [ ] 12.3.4 Add `EnrollAgentRequest` to client.rs
- [ ] 12.3.5 Add `register_with_enrollment` function
- [ ] 12.3.6 Update sync loop to use enrollment
- [ ] 12.3.7 Remove hardcoded `registration_key` usage

---

### Task 12.3.3: Enrollment Token File (Alternative to CLI)

**File**: `C:\Users\{user}\AppData\Local\ai-security\enrollment_token.txt`

```rust
fn read_enrollment_token_from_file() -> Result<String, std::io::Error> {
    let data_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ai-security");

    let token_file = data_dir.join("enrollment_token.txt");

    std::fs::read_to_string(token_file)
        .map(|s| s.trim().to_string())
}
```

**Checklist**:
- [ ] 12.3.8 Add `read_enrollment_token_from_file()` function
- [ ] 12.3.9 Document token file location

---

## 🎨 12.4 Dashboard UI

### Task 12.4.1: Token Management Page

**File**: `cloud-server/dashboard/src/pages/Tokens.jsx`

**UI Components**:

```jsx
// Token list page
<TokensPage>
  <Header>
    <Title>Enrollment Tokens</Title>
    <Button onClick={openCreateModal}>+ New Token</Button>
  </Header>

  <TokenList>
    {tokens.map(token => (
      <TokenCard key={token.id}>
        <TokenName>{token.name}</TokenName>
        <TokenPreview>{token.token_preview}</TokenPreview>
        <UsageCount>{token.uses_count} / {token.max_uses || '∞'}</UsageCount>
        <Status active={token.is_active} />
        <Actions>
          <CopyButton token={token.token} />
          <RevokeButton onRevoke={() => revokeToken(token.id)} />
        </Actions>
      </TokenCard>
    ))}
  </TokenList>
</TokensPage>
```

**Checklist**:
- [ ] 12.4.1 Create `Tokens.jsx` page
- [ ] 12.4.2 Add API service functions
- [ ] 12.4.3 Add route `/tokens`
- [ ] 12.4.4 Add to Sidebar menu

---

### Task 12.4.2: Create Token Modal

```jsx
<CreateTokenModal>
  <Form onSubmit={createToken}>
    <Input
      label="Token Name"
      placeholder="Production Servers"
      required
    />

    <Select label="Expires In">
      <Option value="">Never</Option>
      <Option value="7">7 days</Option>
      <Option value="30">30 days</Option>
      <Option value="90">90 days</Option>
    </Select>

    <Input
      label="Max Uses"
      type="number"
      placeholder="Unlimited"
    />

    <Button type="submit">Generate Token</Button>
  </Form>
</CreateTokenModal>
```

**Checklist**:
- [ ] 12.4.5 Create `CreateTokenModal` component
- [ ] 12.4.6 Form validation
- [ ] 12.4.7 Success state with copy button

---

### Task 12.4.3: Install Instructions Modal

```jsx
<InstallInstructionsModal token={newToken}>
  <Tabs>
    <Tab label="One-Click">
      <CodeBlock>
        {`https://dashboard.accone.vn/install?token=${token}`}
      </CodeBlock>
      <CopyButton />
    </Tab>

    <Tab label="PowerShell">
      <CodeBlock language="powershell">
        {`# Download and install OneShield
Invoke-WebRequest -Uri "https://releases.accone.vn/latest/OneShield.exe" -OutFile "OneShield.exe"
./OneShield.exe --enroll-token=${token}`}
      </CodeBlock>
    </Tab>

    <Tab label="Manual">
      <p>1. Download OneShield from releases page</p>
      <p>2. Create file: %LOCALAPPDATA%\ai-security\enrollment_token.txt</p>
      <p>3. Paste token: <code>{token}</code></p>
      <p>4. Run OneShield.exe</p>
    </Tab>
  </Tabs>
</InstallInstructionsModal>
```

**Checklist**:
- [ ] 12.4.8 Create install instructions modal
- [ ] 12.4.9 Multiple install methods
- [ ] 12.4.10 Copy buttons for each method

---

## 🔒 12.5 Security Considerations

### Token Format

```
ORG_{base64(org_id)}{random_suffix}

Example: ORG_MTVmNDUy_8x7y2z
```

### Validation Rules

| Check | Action |
|-------|--------|
| Token không tồn tại | 401 Unauthorized |
| Token đã revoke | 401 Token Revoked |
| Token hết hạn | 401 Token Expired |
| Token đạt max uses | 403 Max Uses Reached |
| HWID đã register | Re-issue credentials |

### Rate Limiting

```rust
// Limit enrollment attempts
#[middleware]
pub async fn rate_limit_enrollment(req: Request, next: Next) {
    let ip = req.remote_addr();

    // Max 10 enrollments per IP per hour
    if enrollment_count(ip) > 10 {
        return Err(AppError::TooManyRequests);
    }

    next(req).await
}
```

**Checklist**:
- [ ] 12.5.1 Implement token format
- [ ] 12.5.2 Add rate limiting
- [ ] 12.5.3 Add audit logging
- [ ] 12.5.4 Test all validation rules

---

## 🧪 12.6 Testing

### Test Cases

| Test | Expected |
|------|----------|
| Enroll with valid token | Success, agent registered |
| Enroll with expired token | 401 Token Expired |
| Enroll with revoked token | 401 Token Revoked |
| Enroll with max uses reached | 403 Max Uses |
| Re-enroll same HWID | Same agent_id, new token |
| Enroll without token | 401 Unauthorized |

**Checklist**:
- [ ] 12.6.1 Unit tests for token validation
- [ ] 12.6.2 Integration test full enroll flow
- [ ] 12.6.3 Test re-enrollment

---

## 📅 Timeline

| Day | Tasks |
|-----|-------|
| 1 | 12.1 Database + 12.2.1-12.2.4 Token APIs |
| 2 | 12.2.5-12.2.10 Enrollment API |
| 3 | 12.3 Agent changes |
| 4 | 12.4 Dashboard UI |
| 5 | 12.5 Security + 12.6 Testing |
| 6 | 12.7 Personal Organization (B2C) |

---

## 👤 12.7 Personal Organization (B2C Support)

> **Mục tiêu**: Hỗ trợ user lẻ (cá nhân) không thuộc doanh nghiệp

### Vấn đề

Nếu thiết kế cứng nhắc "Phải có Token mới dùng được" → Chặn đường B2C.

### Giải pháp: Personal Organization Pattern

Mỗi user lẻ = 1 Organization có quy mô = 1 người.

```
┌─────────────────────────────────────────────────────────────────┐
│                   PERSONAL ENROLLMENT FLOW                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────────┐    1. Download Personal Edition              │
│   │  User lẻ     │ ──────────────────────────────────────┐     │
│   │  (Cá nhân)   │                                       │     │
│   └──────────────┘                                       ▼     │
│                                              ┌────────────────┐ │
│                                              │ OneShield.exe  │ │
│                                              │ (No token!)    │ │
│                                              └───────┬────────┘ │
│                                                      │          │
│                              2. First run: Show Registration UI │
│                                                      ▼          │
│                                        ┌─────────────────────┐  │
│                                        │  Registration Form  │  │
│                                        │  - Email            │  │
│                                        │  - Password         │  │
│                                        │  - Name (optional)  │  │
│                                        └──────────┬──────────┘  │
│                                                   │             │
│                              3. POST /agent/register_personal   │
│                                                   ▼             │
│                              ┌─────────────────────────────────┐│
│                              │        Cloud Server             ││
│                              │  1. Create Personal Org         ││
│                              │     name: "Personal - {email}"  ││
│                              │  2. Create User (admin role)    ││
│                              │  3. Register Agent              ││
│                              │  4. Return credentials          ││
│                              └─────────────────────────────────┘│
│                                                   │             │
│                              4. Save Identity + Continue        │
│                                                   ▼             │
│                              ┌─────────────────────────────────┐│
│                              │   agent_identity.json           ││
│                              │   + User can login Dashboard    ││
│                              └─────────────────────────────────┘│
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

### Task 12.7.1: Personal Registration API

**File**: `cloud-server/src/handlers/agent.rs`

```rust
// POST /api/v1/agent/register_personal
// Dành cho user lẻ, không cần enrollment token

#[derive(Deserialize)]
pub struct PersonalRegisterRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
    pub hwid: String,
    pub hostname: String,
    pub os_type: String,
    pub os_version: String,
    pub agent_version: String,
}

#[derive(Serialize)]
pub struct PersonalRegisterResponse {
    pub agent_id: Uuid,
    pub agent_token: String,
    pub org_id: Uuid,
    pub org_name: String,
    pub user_id: Uuid,
    pub jwt_token: String,  // For dashboard access
}

pub async fn register_personal(
    State(state): State<AppState>,
    Json(req): Json<PersonalRegisterRequest>,
) -> AppResult<Json<PersonalRegisterResponse>> {

    // 1. Check if email already exists
    if let Some(existing_user) = User::find_by_email(&state.pool, &req.email).await? {
        // User exists - check password and return existing credentials
        if !verify_password(&req.password, &existing_user.password_hash) {
            return Err(AppError::InvalidCredentials);
        }

        // Find or create agent for this user's org
        let agent = find_or_create_agent_for_org(&state.pool, existing_user.org_id, &req).await?;

        return Ok(Json(PersonalRegisterResponse {
            agent_id: agent.id,
            agent_token: agent.token,
            org_id: existing_user.org_id,
            org_name: format!("Personal - {}", req.email),
            user_id: existing_user.id,
            jwt_token: generate_jwt(&existing_user)?,
        }));
    }

    // 2. Create Personal Organization
    let org_name = format!("Personal - {}", req.email);
    let org = Organization::create(&state.pool, CreateOrganization {
        name: org_name.clone(),
        max_agents: Some(3),  // Personal: max 3 devices
    }).await?;

    // 3. Create User (admin of their personal org)
    let password_hash = hash_password(&req.password)?;
    let user = User::create(&state.pool, CreateUser {
        org_id: org.id,
        email: req.email.clone(),
        password_hash,
        name: req.name.unwrap_or_else(|| "Personal User".to_string()),
        role: "admin".to_string(),
    }).await?;

    // 4. Register Agent
    let agent_token = generate_agent_token();
    let endpoint = Endpoint::register(&state.pool, org.id, &req, hash(&agent_token)).await?;

    // 5. Generate JWT for dashboard access
    let jwt_token = generate_jwt(&user)?;

    tracing::info!("Personal user registered: {} (org: {})", req.email, org.id);

    Ok(Json(PersonalRegisterResponse {
        agent_id: endpoint.id,
        agent_token,
        org_id: org.id,
        org_name,
        user_id: user.id,
        jwt_token,
    }))
}
```

**Checklist**:
- [ ] 12.7.1 Create `PersonalRegisterRequest` struct
- [ ] 12.7.2 Create `register_personal` handler
- [ ] 12.7.3 Auto-create Organization
- [ ] 12.7.4 Auto-create User (admin role)
- [ ] 12.7.5 Add route `/api/v1/agent/register_personal`

---

### Task 12.7.2: Agent Personal Mode UI

Khi agent chạy lần đầu không có token → Show registration form trong Tauri app:

```jsx
<PersonalRegistrationModal>
  <Title>Set up OneShield Personal</Title>

  <Form onSubmit={registerPersonal}>
    <Input label="Email" type="email" required />
    <Input label="Password" type="password" required />
    <Checkbox label="I agree to Terms of Service" required />
    <Button type="submit">Create Account & Protect This PC</Button>
  </Form>

  <Divider>or</Divider>
  <Link onClick={showEnterpriseMode}>I have an Enterprise Token</Link>
</PersonalRegistrationModal>
```

**Checklist**:
- [ ] 12.7.6 Create `PersonalRegistration` component
- [ ] 12.7.7 Form validation
- [ ] 12.7.8 Call `/agent/register_personal` API
- [ ] 12.7.9 Save identity on success
- [ ] 12.7.10 Add "Enterprise Token" option

---

### Task 12.7.3: Enrollment Decision Flow

**File**: `core-service/src/logic/cloud_sync/sync.rs`

```rust
async fn handle_enrollment(client: &mut CloudClient, hwid: &str) -> Result<EnrollmentResult> {
    // Priority 1: CLI token
    if let Ok(token) = std::env::var("ENROLLMENT_TOKEN") {
        return enroll_with_token(client, &token, hwid).await;
    }

    // Priority 2: Token file
    if let Ok(token) = read_enrollment_token_from_file() {
        return enroll_with_token(client, &token, hwid).await;
    }

    // Priority 3: Need user input - emit event to show UI
    emit_event("show_enrollment_ui", json!({
        "hwid": hwid,
        "options": ["personal", "enterprise"]
    }));

    Err(CloudError::NeedsUserInput)
}
```

**Checklist**:
- [ ] 12.7.11 Update enrollment flow with priorities
- [ ] 12.7.12 Emit UI event when needed

---

### Task 12.7.4: Pricing Tiers

| Tier | Max Agents | Max Users | Price |
|------|------------|-----------|-------|
| Personal (Free) | 3 | 1 | Free |
| Pro | 10 | 5 | $9/mo |
| Enterprise | Unlimited | Unlimited | Contact |

**Database change**:
```sql
ALTER TABLE organizations ADD COLUMN tier VARCHAR(20) DEFAULT 'personal';
ALTER TABLE organizations ADD COLUMN max_agents INT DEFAULT 3;
```

**Checklist**:
- [ ] 12.7.13 Add tier column
- [ ] 12.7.14 Enforce max_agents limit
- [ ] 12.7.15 Add upgrade flow in Dashboard

---

### Task 12.7.5: Upsell Path

Personal user muốn mở rộng:
1. Login Dashboard
2. Go to Settings → Upgrade
3. Choose Pro/Enterprise
4. Payment (Stripe)
5. Org tier updated
6. Generate tokens for more devices

**Checklist**:
- [ ] 12.7.16 Add upgrade UI
- [ ] 12.7.17 Stripe integration (future)

---

## 🔌 12.8 Standalone/Offline Mode (Optional)

> Cho user không muốn dùng Cloud chút nào

**Behavior**: Khi không có identity, token, và internet:
- ✅ ONNX AI inference (local)
- ✅ Local baseline
- ✅ Heuristic rules
- ❌ Cloud incident sync
- ❌ Remote policy
- ❌ Dashboard view

**Checklist**:
- [ ] 12.8.1 Detect offline scenario
- [ ] 12.8.2 Graceful fallback
- [ ] 12.8.3 UI indicator "Offline Mode"

---

## 📝 Notes

### Breaking Changes
- Remove `registration_key` from constants.rs after migration
- Old agents need re-enrollment with token

### Migration Path
1. Deploy new server with both endpoints
2. Create tokens for existing orgs
3. Gradually migrate agents
4. Deprecate old `/agent/register` endpoint

### Business Model Support

| User Type | Flow | Monetization |
|-----------|------|--------------|
| Enterprise B2B | Admin → Token → Deploy | Per-seat license |
| Personal B2C | Download → Register → Use | Freemium + Pro upgrade |
| Offline/Airgap | Install → Standalone | One-time license |

---

**Created by**: AI Assistant
**Last Updated**: 2025-12-13
**Status**: 📋 PLANNING
