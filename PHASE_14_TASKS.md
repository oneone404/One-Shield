# Phase 14: UI/UX + Adoption

> **Goal**: Sản phẩm có thể demo và mời user dùng thử mà không cần giải thích
> **Duration**: 3-5 ngày
> **Start**: 2025-12-14
> **Status**: 📋 PLANNING

---

## 🎯 Mục Tiêu Phase 14

| # | Mục Tiêu | Ý Nghĩa |
|---|----------|---------|
| 1 | Demo được | Founder có thể demo cho investor/user |
| 2 | Self-service | User tự signup, tự dùng không cần hướng dẫn |
| 3 | Sell-ready | Có thể bán Pro thủ công (Stripe manual) |

---

## 📦 Phase 14 Structure

```
Phase 14
├── 14.1 Dashboard UI (Cloud Console)
│   ├── 14.1.1 Organization Signup Page
│   ├── 14.1.2 Token Management UI
│   ├── 14.1.3 Users Management UI
│   ├── 14.1.4 Empty States + UX Polish
│   └── 14.1.5 Responsive + Mobile Friendly
│
├── 14.2 Desktop App UI (Tauri)
│   ├── 14.2.1 Login/Register Modal
│   ├── 14.2.2 Onboarding Flow
│   ├── 14.2.3 Tier Badge + Status
│   ├── 14.2.4 Upgrade CTA
│   └── 14.2.5 Settings + Account
│
└── 14.3 Polish & Ship
    ├── 14.3.1 Error Handling
    ├── 14.3.2 Loading States
    ├── 14.3.3 i18n (EN/VI)
    └── 14.3.4 Final QA
```

---

# 📋 DETAILED TASKS

---

## 14.1 Dashboard UI (Cloud Console)

### 14.1.1 Organization Signup Page
> Cho phép doanh nghiệp tự đăng ký

**Files:**
- `dashboard/src/pages/Register.jsx` (new)
- `dashboard/src/pages/Register.css`

**UI Elements:**
```
┌─────────────────────────────────────┐
│         🛡️ One-Shield              │
│      Enterprise Security            │
├─────────────────────────────────────┤
│                                     │
│  Organization Name: [____________]  │
│  Admin Email:       [____________]  │
│  Password:          [____________]  │
│  Confirm Password:  [____________]  │
│                                     │
│  [x] I agree to Terms of Service    │
│                                     │
│       [ Create Organization ]       │
│                                     │
│  ─────────────────────────────────  │
│  Already have an account? [Login]   │
│                                     │
└─────────────────────────────────────┘
```

**Tasks:**
- [ ] 14.1.1.1 Create Register.jsx page
- [ ] 14.1.1.2 Form validation (email, password strength)
- [ ] 14.1.1.3 Call /api/v1/auth/register
- [ ] 14.1.1.4 Success → redirect to Dashboard
- [ ] 14.1.1.5 Error handling (email exists, validation)
- [ ] 14.1.1.6 Add route /register in App.jsx

**API:** `POST /api/v1/auth/register`
```json
{
  "email": "admin@company.com",
  "password": "SecurePass123!",
  "name": "Admin Name",
  "organization_name": "Company Inc"
}
```

---

### 14.1.2 Token Management UI
> Tạo, xem, revoke enrollment tokens

**Files:**
- `dashboard/src/pages/Tokens.jsx` (update)
- `dashboard/src/components/TokenCard.jsx` (new)
- `dashboard/src/components/CreateTokenModal.jsx` (new)

**UI Elements:**
```
┌─────────────────────────────────────────────────┐
│  🔑 Enrollment Tokens                           │
├─────────────────────────────────────────────────┤
│  [ + Create New Token ]                         │
│                                                 │
│  ┌─────────────────────────────────────────┐   │
│  │ 📋 Token: ORG_abc123_xyz789             │   │
│  │    Created: 2024-12-13                   │   │
│  │    Uses: 3/10  │  Expires: 7 days        │   │
│  │    [Copy] [Show Install] [Revoke]        │   │
│  └─────────────────────────────────────────┘   │
│                                                 │
│  ┌─────────────────────────────────────────┐   │
│  │ 📋 Token: ORG_def456_uvw123             │   │
│  │    Created: 2024-12-12                   │   │
│  │    Uses: 0/5   │  Expires: 30 days       │   │
│  │    [Copy] [Show Install] [Revoke]        │   │
│  └─────────────────────────────────────────┘   │
│                                                 │
└─────────────────────────────────────────────────┘
```

**Create Token Modal:**
```
┌─────────────────────────────────────┐
│  Create Enrollment Token            │
├─────────────────────────────────────┤
│                                     │
│  Token Name: [________________]     │
│                                     │
│  Max Uses:   [10    ▼]              │
│  (0 = unlimited)                    │
│                                     │
│  Expires In: [7 days ▼]             │
│                                     │
│     [Cancel]  [Create Token]        │
│                                     │
└─────────────────────────────────────┘
```

**Show Install Modal:**
```
┌─────────────────────────────────────┐
│  📥 Install Agent                   │
├─────────────────────────────────────┤
│                                     │
│  Option 1: Download & Run           │
│  ┌─────────────────────────────┐   │
│  │ https://dashboard.accone.vn │   │
│  │ /install?token=ORG_xxx      │   │
│  │              [Copy URL]     │   │
│  └─────────────────────────────┘   │
│                                     │
│  Option 2: PowerShell               │
│  ┌─────────────────────────────┐   │
│  │ OneShield.exe               │   │
│  │ --enroll-token=ORG_xxx      │   │
│  │              [Copy Command] │   │
│  └─────────────────────────────┘   │
│                                     │
│              [Close]                │
│                                     │
└─────────────────────────────────────┘
```

**Tasks:**
- [ ] 14.1.2.1 Token list with status badges
- [ ] 14.1.2.2 Create token modal
- [ ] 14.1.2.3 Show install instructions modal
- [ ] 14.1.2.4 Copy to clipboard functionality
- [ ] 14.1.2.5 Revoke with confirmation
- [ ] 14.1.2.6 Empty state "No tokens yet"
- [ ] 14.1.2.7 Loading skeleton

**APIs:**
- `GET /api/v1/tokens` - List tokens
- `POST /api/v1/tokens` - Create token
- `DELETE /api/v1/tokens/:id` - Revoke token

---

### 14.1.3 Users Management UI
> Xem users trong org, mời user mới (future)

**Files:**
- `dashboard/src/pages/Users.jsx` (new)
- `dashboard/src/components/UserCard.jsx` (new)

**UI Elements:**
```
┌─────────────────────────────────────────────────┐
│  👥 Organization Users                          │
├─────────────────────────────────────────────────┤
│  [ + Invite User ] (disabled - coming soon)     │
│                                                 │
│  ┌─────────────────────────────────────────┐   │
│  │ 👤 Admin User                           │   │
│  │    admin@company.com                     │   │
│  │    Role: Admin  │  Joined: 2024-12-13    │   │
│  │    Last Login: 5 minutes ago             │   │
│  └─────────────────────────────────────────┘   │
│                                                 │
│  ┌─────────────────────────────────────────┐   │
│  │ 👤 Security Analyst                     │   │
│  │    analyst@company.com                   │   │
│  │    Role: Viewer │  Joined: 2024-12-10    │   │
│  │    Last Login: 2 days ago                │   │
│  └─────────────────────────────────────────┘   │
│                                                 │
└─────────────────────────────────────────────────┘
```

**Tasks:**
- [ ] 14.1.3.1 Users list page
- [ ] 14.1.3.2 User card component
- [ ] 14.1.3.3 Role badge (Admin/Viewer)
- [ ] 14.1.3.4 Last login display
- [ ] 14.1.3.5 Invite user button (disabled + tooltip)
- [ ] 14.1.3.6 Empty state

**API:** `GET /api/v1/organization/users`

---

### 14.1.4 Empty States + UX Polish
> Khi không có data, hiển thị hướng dẫn

**Empty States Needed:**

| Page | Empty State Message |
|------|---------------------|
| Dashboard | "No agents connected yet. Create a token to get started!" |
| Agents | "No agents enrolled. [Create Token] to add your first device." |
| Incidents | "🎉 No incidents detected. Your systems are secure!" |
| Tokens | "No enrollment tokens. Create one to deploy agents." |
| Users | "You're the only user. [Coming Soon: Invite team members]" |

**Tasks:**
- [ ] 14.1.4.1 EmptyState component
- [ ] 14.1.4.2 Apply to Dashboard page
- [ ] 14.1.4.3 Apply to Agents page
- [ ] 14.1.4.4 Apply to Incidents page
- [ ] 14.1.4.5 Apply to Tokens page
- [ ] 14.1.4.6 Apply to Users page
- [ ] 14.1.4.7 Add helpful illustrations

---

### 14.1.5 Responsive + Mobile Friendly

**Tasks:**
- [ ] 14.1.5.1 Sidebar collapse on mobile
- [ ] 14.1.5.2 Responsive token cards
- [ ] 14.1.5.3 Responsive user cards
- [ ] 14.1.5.4 Touch-friendly buttons
- [ ] 14.1.5.5 Test on actual mobile devices

---

## 14.2 Desktop App UI (Tauri)

### 14.2.1 Login/Register Modal
> First-time user nhìn thấy khi chưa đăng nhập

**Files:**
- `web-app/src/components/AuthModal.jsx` (new)
- `web-app/src/components/AuthModal.css`

**UI Flow:**
```
App Launch
    ↓
[Check Agent Mode]
    ↓
┌─ Organization Mode ───────────────────┐
│  Has enrollment token                 │
│  → Auto-enroll, no UI needed          │
└───────────────────────────────────────┘
    OR
┌─ Personal Mode ───────────────────────┐
│  No token, needs login                │
│  → Show AuthModal                     │
└───────────────────────────────────────┘
```

**AuthModal UI:**
```
┌─────────────────────────────────────┐
│         🛡️ One-Shield              │
│     Protect Your Computer           │
├─────────────────────────────────────┤
│                                     │
│  [Login] [Register] ← Tab switch    │
│                                     │
│  ─── Login Tab ───                  │
│  Email:    [__________________]     │
│  Password: [__________________]     │
│            [Login & Protect]        │
│                                     │
│  ─── Register Tab ───               │
│  Email:    [__________________]     │
│  Password: [__________________]     │
│  Name:     [__________________]     │
│            [Create Account]         │
│                                     │
│  ─────────────────────────────────  │
│  "Free tier: 1 device protected"    │
│                                     │
└─────────────────────────────────────┘
```

**Tasks:**
- [ ] 14.2.1.1 AuthModal component
- [ ] 14.2.1.2 Login form
- [ ] 14.2.1.3 Register form
- [ ] 14.2.1.4 Tab switching animation
- [ ] 14.2.1.5 Call Tauri `personal_enroll` command
- [ ] 14.2.1.6 Success → close modal, show dashboard
- [ ] 14.2.1.7 Error handling (validation, network)
- [ ] 14.2.1.8 Password show/hide toggle

---

### 14.2.2 Onboarding Flow
> First-time experience sau khi login

**Onboarding Steps:**
```
Step 1: Welcome
┌─────────────────────────────────────┐
│  🎉 Welcome to One-Shield!          │
│                                     │
│  You're now protected.              │
│                                     │
│  Let's set up a few things...       │
│                                     │
│           [Get Started]              │
└─────────────────────────────────────┘

Step 2: Protection Status
┌─────────────────────────────────────┐
│  🛡️ Protection Active              │
│                                     │
│  ✅ AI Engine Running               │
│  ✅ Real-time Monitoring            │
│  ✅ Cloud Sync Connected            │
│                                     │
│           [Continue]                 │
└─────────────────────────────────────┘

Step 3: System Tray
┌─────────────────────────────────────┐
│  📍 Find Me in System Tray          │
│                                     │
│  [Screenshot of system tray]        │
│                                     │
│  One-Shield runs in background      │
│  and protects you 24/7.             │
│                                     │
│           [Got It!]                  │
└─────────────────────────────────────┘
```

**Tasks:**
- [ ] 14.2.2.1 Onboarding component
- [ ] 14.2.2.2 Step 1: Welcome
- [ ] 14.2.2.3 Step 2: Protection status
- [ ] 14.2.2.4 Step 3: System tray info
- [ ] 14.2.2.5 Skip button
- [ ] 14.2.2.6 Don't show again checkbox
- [ ] 14.2.2.7 Store onboarding_complete flag

---

### 14.2.3 Tier Badge + Status
> Hiển thị tier hiện tại

**Header Update:**
```
┌─────────────────────────────────────────────────┐
│ 🛡️ One-Shield          [👤 Free] [⚙️] [—][□][×]│
└─────────────────────────────────────────────────┘
                          ↑
                    Tier Badge
```

**Tier Badges:**
| Tier | Badge | Color |
|------|-------|-------|
| PersonalFree | 👤 Free | Gray |
| PersonalPro | ⭐ Pro | Gold |
| Organization | 🏢 Org | Blue |

**Tasks:**
- [ ] 14.2.3.1 TierBadge component
- [ ] 14.2.3.2 Fetch tier from get_agent_mode
- [ ] 14.2.3.3 Display in header
- [ ] 14.2.3.4 Click → show account info

---

### 14.2.4 Upgrade CTA
> Encourage Free → Pro upgrade

**Upgrade Banner (for Free tier):**
```
┌─────────────────────────────────────────────────┐
│ ⭐ Upgrade to Pro                               │
│ Protect up to 10 devices • $9/month             │
│                              [Upgrade Now]      │
└─────────────────────────────────────────────────┘
```

**Tasks:**
- [ ] 14.2.4.1 UpgradeBanner component
- [ ] 14.2.4.2 Show only for PersonalFree
- [ ] 14.2.4.3 Dismiss button (remember for 7 days)
- [ ] 14.2.4.4 Click → open pricing page in browser
- [ ] 14.2.4.5 Pricing page URL: https://oneshield.vn/pricing

---

### 14.2.5 Settings + Account
> User có thể xem account info

**Settings → Account Tab:**
```
┌─────────────────────────────────────┐
│  👤 Account                         │
├─────────────────────────────────────┤
│                                     │
│  Email: user@example.com            │
│  Tier: Free (1 device)              │
│  Organization: Personal - user@...  │
│                                     │
│  [Upgrade to Pro]                   │
│  [Open Dashboard] → browser         │
│  [Logout]                           │
│                                     │
└─────────────────────────────────────┘
```

**Tasks:**
- [ ] 14.2.5.1 Account tab in Settings
- [ ] 14.2.5.2 Display user info
- [ ] 14.2.5.3 Open Dashboard button
- [ ] 14.2.5.4 Logout functionality
- [ ] 14.2.5.5 Confirmation dialog

---

## 14.3 Polish & Ship

### 14.3.1 Error Handling

**Tasks:**
- [ ] 14.3.1.1 Network error toast
- [ ] 14.3.1.2 Validation error display
- [ ] 14.3.1.3 Session expired handling
- [ ] 14.3.1.4 Generic error fallback

---

### 14.3.2 Loading States

**Tasks:**
- [ ] 14.3.2.1 Loading spinner component
- [ ] 14.3.2.2 Skeleton loaders
- [ ] 14.3.2.3 Button loading state
- [ ] 14.3.2.4 Page loading state

---

### 14.3.3 i18n (EN/VI)

**Tasks:**
- [ ] 14.3.3.1 i18n setup for Dashboard
- [ ] 14.3.3.2 Vietnamese translations
- [ ] 14.3.3.3 Language switcher
- [ ] 14.3.3.4 Persist language preference

---

### 14.3.4 Final QA

**Tasks:**
- [ ] 14.3.4.1 Full flow test: Org signup → Token → Agent
- [ ] 14.3.4.2 Full flow test: Personal signup → App
- [ ] 14.3.4.3 Cross-browser testing
- [ ] 14.3.4.4 Dark mode verification
- [ ] 14.3.4.5 Performance check

---

## 📅 Timeline Estimate

| Day | Focus | Tasks |
|-----|-------|-------|
| 1 | Dashboard: Register + Tokens | 14.1.1, 14.1.2 |
| 2 | Dashboard: Users + Empty States | 14.1.3, 14.1.4 |
| 3 | App: AuthModal + Onboarding | 14.2.1, 14.2.2 |
| 4 | App: Tier Badge + Upgrade | 14.2.3, 14.2.4, 14.2.5 |
| 5 | Polish + QA | 14.3.x |

---

## 🎯 Definition of Done

Phase 14 is complete when:

- [ ] New user can signup on Dashboard
- [ ] Admin can create/revoke tokens
- [ ] New user can login on Desktop App
- [ ] Free tier shows upgrade option
- [ ] No blank/broken pages
- [ ] Works on mobile (Dashboard)
- [ ] Demo-ready

---

## 📦 Deliverables

| # | Deliverable | Who Uses |
|---|-------------|----------|
| 1 | Org Signup Page | Enterprise customers |
| 2 | Token Management | IT Admins |
| 3 | Users Page | Security teams |
| 4 | Personal Login | Individual users |
| 5 | Upgrade Flow | Free users |

---

## 🚀 After Phase 14

You can:
- ✅ Demo to investors
- ✅ Invite beta users
- ✅ Sell Pro manually
- ✅ Get feedback
