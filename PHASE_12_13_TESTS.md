# Phase 12+13 Testing Plan

> **Goal**: Verify core product flows work correctly
> **Duration**: 1-2 days
> **Date**: 2025-12-13
> **Updated**: Applied feedback corrections

---

## 🧪 Test Categories

### 1️⃣ Personal Flow Tests

| # | Test Case | Expected | Status |
|---|-----------|----------|--------|
| P1 | New user register via /personal/enroll | Create user + org (personal_free) + agent | ⏳ |
| P2 | Same user login again (same HWID) | Reuse agent, new token, is_new_user=false | ⏳ |
| P3 | Same user login (different HWID, Free tier) | **BLOCKED** (limit 1 device) | ⏳ |
| P4 | Personal user access dashboard | Limited features (no Tokens/Users tabs) | ⏳ |
| P5 | Personal Pro (10 devices) add 11th device | **BLOCKED** (limit 10) | ⏳ |
| P6a | Personal user GET /tokens | 200 + empty list [] | ⏳ |
| P6b | Personal admin POST /tokens | **403 Forbidden** | ⏳ |
| P7 | Invalid password login | 401 Invalid credentials | ⏳ |

### 2️⃣ Organization Flow Tests

| # | Test Case | Expected | Status |
|---|-----------|----------|--------|
| O1 | Org admin login dashboard | Full features visible (Tokens, Users tabs) | ⏳ |
| O2 | Org admin create token | 200 + token returned | ⏳ |
| O3 | Org **viewer** try create token | **403 Forbidden** | ⏳ |
| O4 | Org admin revoke token | 200 + success | ⏳ |
| O5 | Org **viewer** try revoke token | **403 Forbidden** | ⏳ |
| O6 | Agent enroll with valid token | 200 + agent_id + agent_token | ⏳ |
| O7 | Agent enroll with **revoked** token | **403** (token revoked) | ⏳ |
| O8 | Agent enroll with **exhausted** token (max_uses reached) | **403** (usage limit exceeded) | ⏳ |
| O9 | Agent enroll with **expired** token | **403** | ⏳ |

### 3️⃣ Edge Cases (Critical)

| # | Test Case | Expected | Status |
|---|-----------|----------|--------|
| E1 | Personal user call /agent/enroll (no token) | 401 Unauthorized | ⏳ |
| E2 | **Org user** call /personal/enroll | **403 Forbidden** (must use enrollment token) | ⏳ |
| E3 | Duplicate email via /personal/enroll | LOGIN flow (not error) | ⏳ |
| E4 | Duplicate email via /auth/register | **409 Already exists** | ⏳ |
| E5 | Token usage count increments atomically | uses_count += 1 after enroll | ⏳ |
| E6 | HWID already exists in same org | Reuse agent, update token | ⏳ |

### 4️⃣ JWT Scope Tests

| # | Test Case | Expected | Status |
|---|-----------|----------|--------|
| J1 | Personal JWT call GET /users | **403 Forbidden** (org feature) | ⏳ |
| J2 | Personal JWT call POST /tokens | **403 Forbidden** | ⏳ |
| J3 | Org viewer JWT call POST /tokens | **403 Forbidden** | ⏳ |
| J4 | Org admin JWT call POST /tokens | 200 + token | ⏳ |

---

## 🔧 Test Environment

- **API Server**: https://api.accone.vn
- **Dashboard**: https://dashboard.accone.vn
- **Local Agent**: core-service

---

## 📝 Test Execution Scripts

### Test P1: New User Register
```bash
curl -X POST https://api.accone.vn/api/v1/personal/enroll \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test-p1@example.com",
    "password": "Test123!@#",
    "name": "Test User P1",
    "hwid": "TEST-HWID-001",
    "hostname": "TestPC-001",
    "os_type": "Windows",
    "os_version": "Windows 11",
    "agent_version": "0.1.0"
  }'
```

**Expected Response:**
```json
{
  "user_id": "uuid",
  "jwt_token": "eyJ...",
  "agent_id": "uuid",
  "agent_token": "uuid",
  "org_id": "uuid",
  "org_name": "Personal - test-p1@example.com",
  "tier": "personal_free",
  "is_new_user": true
}
```

---

### Test P3: Free Tier Add 2nd Device (BLOCKED)
```bash
# Login with same email but DIFFERENT HWID
curl -X POST https://api.accone.vn/api/v1/personal/enroll \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test-p1@example.com",
    "password": "Test123!@#",
    "hwid": "TEST-HWID-002",
    "hostname": "TestPC-002",
    "os_type": "Windows",
    "os_version": "Windows 11",
    "agent_version": "0.1.0"
  }'
```

**Expected Response (422):**
```json
{
  "error": "Device limit reached (1/1). Upgrade to add more devices."
}
```

---

### Test E2: Org User Call /personal/enroll (BLOCKED)
```bash
# Org user tries to bypass enrollment tokens
curl -X POST https://api.accone.vn/api/v1/personal/enroll \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@demo.com",
    "password": "admin123",
    "hwid": "BYPASS-HWID",
    "hostname": "BypassPC",
    "os_type": "Windows",
    "os_version": "Windows 11",
    "agent_version": "0.1.0"
  }'
```

**Expected Response (403):**
```json
{
  "error": "Forbidden"
}
```

---

### Test O2: Org Admin Create Token
```bash
# Step 1: Login to get JWT
JWT=$(curl -s -X POST https://api.accone.vn/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@demo.com", "password": "admin123"}' \
  | jq -r '.token')

# Step 2: Create token
curl -X POST https://api.accone.vn/api/v1/tokens \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT" \
  -d '{
    "name": "Test Token O2",
    "max_uses": 5,
    "expires_in_days": 7
  }'
```

**Expected Response (200):**
```json
{
  "id": "uuid",
  "token": "ORG_xxxxxxxx_xxxxxxxx",
  "install_url": "https://dashboard.accone.vn/install?token=...",
  "install_command": "OneShield.exe --enroll-token=ORG_..."
}
```

---

### Test O6: Agent Enroll with Token
```bash
curl -X POST https://api.accone.vn/api/v1/agent/enroll \
  -H "Content-Type: application/json" \
  -d '{
    "enrollment_token": "ORG_xxxxxxxx_xxxxxxxx",
    "hwid": "AGENT-HWID-001",
    "hostname": "AgentPC-001",
    "os_type": "Windows",
    "os_version": "Windows 11",
    "agent_version": "0.1.0"
  }'
```

**Expected Response (200):**
```json
{
  "agent_id": "uuid",
  "agent_token": "uuid",
  "org_id": "uuid"
}
```

---

## ✅ Test Results Summary

| Category | Passed | Failed | Blocked |
|----------|--------|--------|---------|
| Personal Flow | 0/8 | 0 | 0 |
| Organization Flow | 0/9 | 0 | 0 |
| Edge Cases | 0/6 | 0 | 0 |
| JWT Scope | 0/4 | 0 | 0 |
| **Total** | **0/27** | **0** | **0** |

---

## 🐛 Bugs Found

| # | Test | Issue | Severity | Fix Status |
|---|------|-------|----------|------------|
| - | - | - | - | - |

---

## 🧹 Cleanup Checklist

After testing, clean up:

- [ ] Delete test users (test-*@example.com)
- [ ] Delete test organizations (Personal - test-*)
- [ ] Revoke all test tokens
- [ ] Remove test agents (TEST-HWID-*, AGENT-HWID-*)
- [ ] Clear any test incidents

**SQL Cleanup (run on DB):**
```sql
-- Delete test data (be careful!)
DELETE FROM endpoints WHERE hwid LIKE 'TEST-%' OR hwid LIKE 'AGENT-%';
DELETE FROM users WHERE email LIKE 'test-%@example.com';
DELETE FROM organizations WHERE name LIKE 'Personal - test-%';
DELETE FROM organization_tokens WHERE name LIKE 'Test Token%';
```

---

## 📋 Notes

- Run tests in order (some depend on previous)
- E2 fix deployed: Org users blocked from /personal/enroll
- `is_new_user` field is returned by backend ✅
- Edge cases are critical - they protect against misuse
