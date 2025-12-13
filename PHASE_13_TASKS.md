# Phase 13: Authentication & Product Workflow

> **Mục tiêu**: Phân tách rõ ràng luồng Personal (Free/Pro) vs Organization (Enterprise)
> **Effort**: ~8-12 giờ
> **Priority**: 🔴 HIGH (Core product architecture)
> **Last Updated**: 2025-12-13

---

## 📋 WORKFLOW CHỐT (FINAL DESIGN)

### Nguyên tắc vàng:

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRODUCT ENTRY POINTS                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   👤 PERSONAL (Free/Pro)         │    🏢 ORGANIZATION            │
│   ─────────────────────          │    ────────────────           │
│   Entry: APP (Download)          │    Entry: DASHBOARD (Web)     │
│   Auth: Login/Register in App    │    Auth: Admin creates tokens │
│   Agent: After user login        │    Agent: By enrollment token │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 🎯 Mode Detection Rule:

```rust
// Trong Agent
if enrollment_token.exists() {
    // ORGANIZATION MODE
    // → NO Login/Register UI
    // → Use token to enroll
} else {
    // PERSONAL MODE
    // → REQUIRE Login/Register UI
    // → Create personal org
}
```

---

## 🔄 FLOW DIAGRAMS

### 1️⃣ Personal Flow (Free/Pro)

```
┌─────────────────────────────────────────────────────────────────┐
│                    PERSONAL USER FLOW                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   User Download               App First Run                     │
│   ────────────               ──────────────                     │
│        │                          │                             │
│        ▼                          ▼                             │
│   ┌─────────┐            ┌─────────────────┐                   │
│   │Download │            │ No Token Found  │                   │
│   │from Web │───────────►│ Show Login/Reg  │                   │
│   └─────────┘            └────────┬────────┘                   │
│                                   │                             │
│                    ┌──────────────┴──────────────┐             │
│                    ▼                             ▼              │
│            ┌────────────┐               ┌────────────┐         │
│            │  Login     │               │  Register  │         │
│            │  (existing)│               │  (new user)│         │
│            └─────┬──────┘               └──────┬─────┘         │
│                  │                             │                │
│                  └──────────────┬──────────────┘                │
│                                 ▼                               │
│                    ┌────────────────────────┐                  │
│                    │ POST /auth/login       │                  │
│                    │   or /personal/enroll  │                  │
│                    └───────────┬────────────┘                  │
│                                │                                │
│                                ▼                                │
│              ┌──────────────────────────────────┐              │
│              │         Backend Logic            │              │
│              │  ┌─────────────────────────────┐ │              │
│              │  │ 1. Find/Create User         │ │              │
│              │  │ 2. Find/Create Personal Org │ │              │
│              │  │    name: "Personal - email" │ │              │
│              │  │ 3. Register Agent           │ │              │
│              │  │ 4. Return JWT + Agent Token │ │              │
│              │  └─────────────────────────────┘ │              │
│              └────────────────┬─────────────────┘              │
│                               │                                 │
│                               ▼                                 │
│              ┌──────────────────────────────────┐              │
│              │   App Saves Identity             │              │
│              │   - agent_id                     │              │
│              │   - agent_token                  │              │
│              │   - user_jwt (for dashboard)     │              │
│              └────────────────┬─────────────────┘              │
│                               │                                 │
│                               ▼                                 │
│              ┌──────────────────────────────────┐              │
│              │     ✅ Agent Running             │              │
│              │     ✅ User can access Dashboard │              │
│              └──────────────────────────────────┘              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2️⃣ Organization Flow (Enterprise)

```
┌─────────────────────────────────────────────────────────────────┐
│                   ORGANIZATION FLOW                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Admin Signup                 Token Creation                   │
│   ────────────                 ──────────────                   │
│        │                            │                           │
│        ▼                            ▼                           │
│   ┌───────────────┐       ┌─────────────────────┐              │
│   │ Dashboard     │       │ Create Token       │              │
│   │ Register Org  │──────►│ ORG_0c86c33f_xxx   │              │
│   └───────────────┘       └─────────┬───────────┘              │
│                                     │                           │
│                                     ▼                           │
│              ┌──────────────────────────────────┐              │
│              │    IT Admin Deploys Agent        │              │
│              │                                  │              │
│              │  Option A: CLI                   │              │
│              │  > OneShield.exe --enroll=ORG_xx │              │
│              │                                  │              │
│              │  Option B: Token File            │              │
│              │  > enrollment_token.txt          │              │
│              │                                  │              │
│              │  Option C: Group Policy          │              │
│              │  > MSI with embedded token       │              │
│              └────────────────┬─────────────────┘              │
│                               │                                 │
│                               ▼                                 │
│              ┌──────────────────────────────────┐              │
│              │     Agent Starts                 │              │
│              │     Finds enrollment token       │              │
│              │     → ORGANIZATION MODE          │              │
│              │     → NO Login UI                │              │
│              └────────────────┬─────────────────┘              │
│                               │                                 │
│                               ▼                                 │
│              ┌──────────────────────────────────┐              │
│              │   POST /agent/enroll             │              │
│              │   {                              │              │
│              │     enrollment_token: "ORG_xxx", │              │
│              │     hwid: "...",                 │              │
│              │     hostname: "PC-001"           │              │
│              │   }                              │              │
│              └────────────────┬─────────────────┘              │
│                               │                                 │
│                               ▼                                 │
│              ┌──────────────────────────────────┐              │
│              │     ✅ Agent Enrolled            │              │
│              │     ✅ Visible in Dashboard      │              │
│              │     ❌ No user login required    │              │
│              └──────────────────────────────────┘              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📊 Feature Matrix

| Feature | Personal Free | Personal Pro | Organization |
|---------|---------------|--------------|--------------|
| **Entry Point** | App | App | Dashboard |
| **Signup** | In-App | In-App | Dashboard |
| **Max Devices** | 1 | 10 | Unlimited |
| **Max Users** | 1 | 1 | Unlimited |
| **Agent Auth** | User Login | User Login | Token |
| **Dashboard** | ✅ Limited | ✅ Limited | ✅ Full |
| **Tokens Tab** | ❌ Hidden | ❌ Hidden | ✅ Admin only |
| **Users Tab** | ❌ Hidden | ❌ Hidden | ✅ Yes |
| **Audit Logs** | ❌ | ❌ | ✅ |
| **API Access** | ❌ | ❌ | ✅ |
| **SSO/SAML** | ❌ | ❌ | ✅ Optional |
| **Price** | Free | $9/mo | Contract |

---

## 🏗️ IMPLEMENTATION TASKS

### 13.1 Backend: Role-Based Access Control

#### Task 13.1.1: Add `require_admin` helper

**File**: `cloud-server/src/middleware/auth.rs`

```rust
/// Check if user has admin role
pub fn require_admin(user: &UserContext) -> Result<(), AppError> {
    if user.role != "admin" {
        return Err(AppError::Forbidden);
    }
    Ok(())
}
```

**Checklist**:
- [ ] 13.1.1 Add `require_admin()` function
- [ ] 13.1.2 Apply to `create_token` handler
- [ ] 13.1.3 Apply to `revoke_token` handler
- [ ] 13.1.4 Test with non-admin user

---

#### Task 13.1.2: Add Organization Tier Check

**File**: `cloud-server/src/models/organization.rs`

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum OrgTier {
    PersonalFree,
    PersonalPro,
    Organization,
    Enterprise,
}

impl Organization {
    pub fn tier(&self) -> OrgTier {
        match self.tier.as_str() {
            "personal_free" => OrgTier::PersonalFree,
            "personal_pro" => OrgTier::PersonalPro,
            "organization" => OrgTier::Organization,
            "enterprise" => OrgTier::Enterprise,
            _ => OrgTier::PersonalFree,
        }
    }

    pub fn can_create_tokens(&self) -> bool {
        matches!(self.tier(), OrgTier::Organization | OrgTier::Enterprise)
    }

    pub fn max_devices(&self) -> i32 {
        match self.tier() {
            OrgTier::PersonalFree => 1,
            OrgTier::PersonalPro => 10,
            _ => self.max_agents.unwrap_or(1000),
        }
    }
}
```

**Checklist**:
- [ ] 13.1.5 Add `OrgTier` enum
- [ ] 13.1.6 Add tier methods
- [ ] 13.1.7 Add `can_create_tokens()` check
- [ ] 13.1.8 Add `max_devices()` logic

---

#### Task 13.1.3: Personal Registration API

**File**: `cloud-server/src/handlers/auth.rs`

```rust
// POST /api/v1/personal/enroll
// For personal users signing up via the app
#[derive(Deserialize)]
pub struct PersonalEnrollRequest {
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
pub struct PersonalEnrollResponse {
    // User info
    pub user_id: Uuid,
    pub jwt_token: String,
    // Agent info
    pub agent_id: Uuid,
    pub agent_token: String,
    // Org info
    pub org_id: Uuid,
    pub org_name: String,
    pub tier: String,
}

pub async fn personal_enroll(
    State(state): State<AppState>,
    Json(req): Json<PersonalEnrollRequest>,
) -> AppResult<Json<PersonalEnrollResponse>> {
    // 1. Check if user exists
    if let Some(user) = User::find_by_email(&state.pool, &req.email).await? {
        // Login flow - verify password
        if !verify_password(&req.password, &user.password_hash)? {
            return Err(AppError::InvalidCredentials);
        }

        // Get org
        let org = Organization::get_by_id(&state.pool, user.org_id).await?
            .ok_or(AppError::InternalError("Org not found".into()))?;

        // Check device limit
        let device_count = Endpoint::count_by_org(&state.pool, org.id).await?;
        if device_count >= org.max_devices() as i64 {
            return Err(AppError::ValidationError(
                format!("Device limit reached ({}/{})", device_count, org.max_devices())
            ));
        }

        // Register or update agent
        let (agent_id, agent_token) = register_or_update_agent(
            &state.pool,
            org.id,
            &req.hwid,
            &req.hostname
        ).await?;

        // Generate JWT
        let jwt = generate_jwt(&user, &state.config)?;

        return Ok(Json(PersonalEnrollResponse {
            user_id: user.id,
            jwt_token: jwt,
            agent_id,
            agent_token,
            org_id: org.id,
            org_name: org.name,
            tier: org.tier,
        }));
    }

    // 2. New user - create account
    let org_name = format!("Personal - {}", req.email);

    // Create org
    let org = Organization::create(&state.pool, CreateOrganization {
        name: org_name.clone(),
        tier: Some("personal_free".to_string()),
        max_agents: Some(1),
    }).await?;

    // Create user (admin of their personal org)
    let password_hash = hash_password(&req.password)?;
    let user = User::create(&state.pool, CreateUser {
        org_id: org.id,
        email: req.email.clone(),
        password_hash,
        name: req.name.unwrap_or("Personal User".into()),
        role: "admin".to_string(),
    }).await?;

    // Register agent
    let agent_token = generate_agent_token();
    let agent = Endpoint::register(&state.pool, org.id, &req, hash(&agent_token)).await?;

    // Generate JWT
    let jwt = generate_jwt(&user, &state.config)?;

    Ok(Json(PersonalEnrollResponse {
        user_id: user.id,
        jwt_token: jwt,
        agent_id: agent.id,
        agent_token,
        org_id: org.id,
        org_name,
        tier: "personal_free".to_string(),
    }))
}
```

**Checklist**:
- [ ] 13.1.9 Create `PersonalEnrollRequest` struct
- [ ] 13.1.10 Create `PersonalEnrollResponse` struct
- [ ] 13.1.11 Implement `personal_enroll` handler
- [ ] 13.1.12 Add device limit check
- [ ] 13.1.13 Add route `/api/v1/personal/enroll`

---

### 13.2 Agent: Mode Detection & Login UI

#### Task 13.2.1: Mode Detection

**File**: `core-service/src/logic/cloud_sync/sync.rs`

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum AgentMode {
    Organization,  // Has enrollment token
    Personal,      // Needs user login
}

pub fn detect_mode() -> AgentMode {
    if crate::constants::get_enrollment_token_any().is_some() {
        AgentMode::Organization
    } else {
        AgentMode::Personal
    }
}
```

**Checklist**:
- [ ] 13.2.1 Add `AgentMode` enum
- [ ] 13.2.2 Add `detect_mode()` function
- [ ] 13.2.3 Export to frontend via Tauri command

---

#### Task 13.2.2: Personal Login/Register UI

**File**: `web-app/src/components/PersonalAuth.jsx`

```jsx
// Show when: detect_mode() == Personal && no identity

<PersonalAuthModal>
  <Tabs value={tab} onChange={setTab}>
    <Tab value="login">Login</Tab>
    <Tab value="register">Register</Tab>
  </Tabs>

  {tab === 'login' && (
    <Form onSubmit={handleLogin}>
      <Input type="email" placeholder="Email" />
      <Input type="password" placeholder="Password" />
      <Button>Login & Protect This PC</Button>
    </Form>
  )}

  {tab === 'register' && (
    <Form onSubmit={handleRegister}>
      <Input type="email" placeholder="Email" />
      <Input type="password" placeholder="Password" />
      <Input type="password" placeholder="Confirm Password" />
      <Checkbox>I agree to Terms</Checkbox>
      <Button>Create Account</Button>
    </Form>
  )}
</PersonalAuthModal>
```

**Checklist**:
- [ ] 13.2.4 Create `PersonalAuth.jsx` component
- [ ] 13.2.5 Login form
- [ ] 13.2.6 Register form
- [ ] 13.2.7 Call `/personal/enroll` API
- [ ] 13.2.8 Save identity on success
- [ ] 13.2.9 Trigger sync loop after auth

---

#### Task 13.2.3: Tauri Commands for Personal Auth

**File**: `core-service/src/api/auth.rs`

```rust
#[tauri::command]
pub async fn get_agent_mode() -> Result<String, String> {
    let mode = cloud_sync::detect_mode();
    Ok(match mode {
        AgentMode::Organization => "organization".to_string(),
        AgentMode::Personal => "personal".to_string(),
    })
}

#[tauri::command]
pub async fn personal_enroll(
    email: String,
    password: String,
    is_register: bool,
) -> Result<PersonalEnrollResult, String> {
    // Get HWID
    let hwid = identity::get_hwid();
    let hostname = hostname::get().unwrap_or("unknown".into()).to_string_lossy().to_string();

    // Call API
    let client = reqwest::Client::new();
    let response = client
        .post(&format!("{}/api/v1/personal/enroll", constants::get_cloud_url()))
        .json(&json!({
            "email": email,
            "password": password,
            "hwid": hwid,
            "hostname": hostname,
            "os_type": "Windows",
            "os_version": get_os_version(),
            "agent_version": env!("CARGO_PKG_VERSION"),
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        let error = response.text().await.unwrap_or_default();
        return Err(error);
    }

    let result: PersonalEnrollResponse = response.json().await.map_err(|e| e.to_string())?;

    // Save identity
    let mut identity_mgr = identity::get_identity_manager().write();
    identity_mgr.save_identity(
        result.agent_id,
        result.agent_token.clone(),
        result.org_id,
        &constants::get_cloud_url(),
    ).map_err(|e| e.to_string())?;

    // Save JWT for dashboard access
    save_user_jwt(&result.jwt_token)?;

    // Trigger sync loop
    cloud_sync::restart_sync_loop();

    Ok(PersonalEnrollResult {
        success: true,
        tier: result.tier,
    })
}
```

**Checklist**:
- [ ] 13.2.10 Add `get_agent_mode` command
- [ ] 13.2.11 Add `personal_enroll` command
- [ ] 13.2.12 Save JWT for dashboard access
- [ ] 13.2.13 Restart sync loop after auth

---

### 13.3 Dashboard: Feature Gating by Tier

#### Task 13.3.1: Get Org Tier API

**File**: `cloud-server/src/handlers/organization.rs`

```rust
// GET /api/v1/organization
// Returns org info including tier
#[derive(Serialize)]
pub struct OrgInfoResponse {
    pub id: Uuid,
    pub name: String,
    pub tier: String,
    pub max_agents: i32,
    pub current_agents: i64,
    pub features: OrgFeatures,
}

#[derive(Serialize)]
pub struct OrgFeatures {
    pub can_create_tokens: bool,
    pub can_manage_users: bool,
    pub can_view_audit_logs: bool,
    pub can_access_api: bool,
}
```

**Checklist**:
- [ ] 13.3.1 Update org endpoint with tier/features
- [ ] 13.3.2 Add `OrgFeatures` struct

---

#### Task 13.3.2: Hide/Show Features by Tier

**File**: `dashboard/src/App.jsx`

```jsx
// Conditionally render routes based on org tier

function App() {
  const { org, loading } = useOrg();

  if (loading) return <Loading />;

  const isOrg = org?.tier === 'organization' || org?.tier === 'enterprise';

  return (
    <Routes>
      {/* Always available */}
      <Route path="/" element={<Dashboard />} />
      <Route path="/devices" element={<Devices />} />
      <Route path="/incidents" element={<Incidents />} />

      {/* Organization only */}
      {isOrg && (
        <>
          <Route path="/tokens" element={<Tokens />} />
          <Route path="/users" element={<Users />} />
          <Route path="/audit" element={<AuditLogs />} />
        </>
      )}

      {/* Settings (all) */}
      <Route path="/settings" element={<Settings />} />
    </Routes>
  );
}
```

**Sidebar**:
```jsx
function Sidebar() {
  const { org } = useOrg();
  const isOrg = org?.features?.can_create_tokens;

  return (
    <nav>
      <NavItem to="/" icon={Home}>Dashboard</NavItem>
      <NavItem to="/devices" icon={Monitor}>Devices</NavItem>
      <NavItem to="/incidents" icon={Alert}>Incidents</NavItem>

      {isOrg && (
        <>
          <NavItem to="/tokens" icon={Key}>Tokens</NavItem>
          <NavItem to="/users" icon={Users}>Users</NavItem>
        </>
      )}

      <NavItem to="/settings" icon={Settings}>Settings</NavItem>
    </nav>
  );
}
```

**Checklist**:
- [ ] 13.3.3 Create `useOrg` hook
- [ ] 13.3.4 Conditionally render Tokens menu
- [ ] 13.3.5 Conditionally render Users menu
- [ ] 13.3.6 Block routes for Personal tier

---

#### Task 13.3.3: Create Org Context

**File**: `dashboard/src/context/OrgContext.jsx`

```jsx
const OrgContext = createContext(null);

export function OrgProvider({ children }) {
  const [org, setOrg] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchOrg();
  }, []);

  const fetchOrg = async () => {
    try {
      const data = await api.getOrganization();
      setOrg(data);
    } catch (err) {
      console.error('Failed to fetch org:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <OrgContext.Provider value={{ org, loading, refetch: fetchOrg }}>
      {children}
    </OrgContext.Provider>
  );
}

export const useOrg = () => useContext(OrgContext);
```

**Checklist**:
- [ ] 13.3.7 Create `OrgContext.jsx`
- [ ] 13.3.8 Create `useOrg` hook
- [ ] 13.3.9 Wrap App in OrgProvider

---

### 13.4 Dashboard: Organization Signup

#### Task 13.4.1: Org Registration Page

**File**: `dashboard/src/pages/OrgSignup.jsx`

```jsx
// Route: /signup/organization

<OrgSignupPage>
  <Hero>
    <Title>Start Your Organization</Title>
    <Subtitle>Protect your entire team with One-Shield Enterprise</Subtitle>
  </Hero>

  <Form onSubmit={handleSignup}>
    <Input label="Organization Name" required />
    <Input label="Admin Email" type="email" required />
    <Input label="Password" type="password" required />
    <Input label="Confirm Password" type="password" required />

    <Select label="Company Size">
      <Option>1-10 employees</Option>
      <Option>11-50 employees</Option>
      <Option>51-200 employees</Option>
      <Option>200+ employees</Option>
    </Select>

    <Checkbox>I agree to Terms of Service</Checkbox>

    <Button type="submit">Create Organization</Button>
  </Form>

  <Divider>or</Divider>
  <Link to="/login">Already have an account? Login</Link>
</OrgSignupPage>
```

**Checklist**:
- [ ] 13.4.1 Create `OrgSignup.jsx` page
- [ ] 13.4.2 Form validation
- [ ] 13.4.3 Call `/api/v1/auth/register` with `organization_name`
- [ ] 13.4.4 Auto-login after signup
- [ ] 13.4.5 Redirect to `/tokens` for first token creation

---

### 13.5 Security: Token API Role Check

#### Task 13.5.1: Update Token Handlers

**File**: `cloud-server/src/handlers/tokens.rs`

```rust
pub async fn create_token(
    State(state): State<AppState>,
    user: UserContext,
    Json(req): Json<CreateTokenRequest>,
) -> AppResult<Json<CreateTokenResponse>> {
    // Check admin role
    if user.role != "admin" {
        return Err(AppError::Forbidden);
    }

    // Check org tier can create tokens
    let org = Organization::get_by_id(&state.pool, user.org_id).await?
        .ok_or(AppError::NotFound("Organization not found".into()))?;

    if !org.can_create_tokens() {
        return Err(AppError::Forbidden);  // Personal tier cannot create tokens
    }

    // ... rest of handler
}

pub async fn revoke_token(
    State(state): State<AppState>,
    user: UserContext,
    Path(token_id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    // Check admin role
    if user.role != "admin" {
        return Err(AppError::Forbidden);
    }

    // ... rest of handler
}
```

**Checklist**:
- [ ] 13.5.1 Add admin check to `create_token`
- [ ] 13.5.2 Add admin check to `revoke_token`
- [ ] 13.5.3 Add tier check to `create_token`
- [ ] 13.5.4 Add tier check to `list_tokens` (optional)

---

## 📅 Timeline

| Day | Tasks | Effort |
|-----|-------|--------|
| 1 | 13.1 RBAC + Tier check | 2h |
| 2 | 13.1.9-13 Personal enroll API | 2h |
| 3 | 13.2 Agent mode detection + UI | 3h |
| 4 | 13.3 Dashboard feature gating | 2h |
| 5 | 13.4 Org signup + 13.5 Security | 2h |
| 6 | Testing + Bug fixes | 1h |

**Total**: ~12 hours

---

## 🔄 Migration Notes

### For Existing Users

1. **Existing Personal Orgs**: Auto-set `tier = 'personal_free'`
2. **Existing Orgs with Tokens**: Auto-set `tier = 'organization'`
3. **Existing Agents**: Continue working (backwards compatible)

### Database Migration

```sql
-- Set tier for existing orgs
UPDATE organizations
SET tier = CASE
    WHEN name LIKE 'Personal - %' THEN 'personal_free'
    ELSE 'organization'
END
WHERE tier IS NULL OR tier = 'personal';
```

---

## 📝 API Summary

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /personal/enroll` | Public | Personal user signup/login + agent |
| `POST /agent/enroll` | Token | Org agent enrollment |
| `GET /tokens` | JWT (Admin + Org tier) | List tokens |
| `POST /tokens` | JWT (Admin + Org tier) | Create token |
| `DELETE /tokens/:id` | JWT (Admin + Org tier) | Revoke token |

---

## ✅ Done Criteria

- [ ] Personal users can login/register in App
- [ ] Personal users see limited Dashboard (no Tokens/Users)
- [ ] Organization admins can create tokens
- [ ] Organization agents enroll via token (no login UI)
- [ ] Viewer role cannot create/revoke tokens
- [ ] Device limits enforced per tier
- [ ] All APIs have proper role + tier checks

---

**Created by**: AI Assistant
**Last Updated**: 2025-12-13
**Status**: 📋 PLANNING
