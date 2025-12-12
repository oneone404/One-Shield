# 📋 Phase 11 - Management Dashboard (v3.0)

> **Mục tiêu**: Xây dựng Cloud Management Dashboard để quản lý tất cả agents, incidents, và policies từ một nơi.

**Ngày tạo**: 2025-12-12
**Dự kiến bắt đầu**: TBD
**Effort ước tính**: ~3-5 ngày

---

## 🎯 Mục Tiêu Phase 11

1. **Web Dashboard** - React app cho admin quản lý
2. **Real-time Monitoring** - View tất cả agents và incidents
3. **Policy Management** - Tạo/edit policies cho agents
4. **Compliance Reports** - ISO 27001 compliance reporting

---

## ✅ Tasks

### 11.1 Cloud Dashboard (React Web App)

```
📁 cloud-dashboard/
├── src/
│   ├── components/
│   │   ├── Layout/
│   │   │   ├── Sidebar.jsx
│   │   │   ├── Header.jsx
│   │   │   └── Footer.jsx
│   │   ├── Dashboard/
│   │   │   ├── StatCards.jsx
│   │   │   ├── AgentMap.jsx
│   │   │   └── IncidentChart.jsx
│   │   ├── Agents/
│   │   │   ├── AgentList.jsx
│   │   │   ├── AgentDetail.jsx
│   │   │   └── AgentStatus.jsx
│   │   ├── Incidents/
│   │   │   ├── IncidentList.jsx
│   │   │   ├── IncidentDetail.jsx
│   │   │   └── IncidentTimeline.jsx
│   │   ├── Policies/
│   │   │   ├── PolicyList.jsx
│   │   │   ├── PolicyEditor.jsx
│   │   │   └── PolicyAssign.jsx
│   │   └── Reports/
│   │       ├── ExecutiveReport.jsx
│   │       └── ComplianceReport.jsx
│   ├── pages/
│   │   ├── Login.jsx
│   │   ├── Dashboard.jsx
│   │   ├── Agents.jsx
│   │   ├── Incidents.jsx
│   │   ├── Policies.jsx
│   │   └── Reports.jsx
│   ├── services/
│   │   └── api.js
│   └── App.jsx
```

**Tasks**:
- [x] 11.1.1 Setup React + Vite project ✅ (2025-12-12)
- [x] 11.1.2 Create Login page với JWT auth ✅ (2025-12-12)
- [x] 11.1.3 Create Dashboard với stat cards ✅ (2025-12-12)
- [ ] 11.1.4 Create Agents list (show online/offline)
- [ ] 11.1.5 Create Agent detail view
- [ ] 11.1.6 Create Incidents list
- [ ] 11.1.7 Create Incident detail + timeline
- [ ] 11.1.8 Create Policy list/editor
- [ ] 11.1.9 Create Executive Report

---

### 11.2 Cloud Server API Extensions

**Tasks**:
- [ ] 11.2.1 Add user authentication (login/register)
- [ ] 11.2.2 Add agent online/offline status tracking
- [ ] 11.2.3 Add incident statistics endpoint
- [ ] 11.2.4 Add policy CRUD operations
- [ ] 11.2.5 Add report generation endpoints
- [ ] 11.2.6 Add WebSocket for real-time updates

---

### 11.3 Real-time Updates

**Technologies**:
- WebSocket (Axum + tokio-tungstenite)
- Server-Sent Events (SSE) as fallback

**Events to stream**:
- Agent status changes (online/offline)
- New incidents
- Heartbeat updates
- Policy updates

**Tasks**:
- [ ] 11.3.1 Add WebSocket support to cloud-server
- [ ] 11.3.2 Broadcast agent status changes
- [ ] 11.3.3 Broadcast new incidents
- [ ] 11.3.4 React hook for WebSocket connection

---

### 11.6 🏆 Enterprise Agent Identity (NEW!)

**Mục tiêu**: Agent ID cố định theo máy, không tạo mới khi restart (Chuẩn CrowdStrike/SentinelOne)

**Features**:
- Hardware-bound Identity (HWID)
- Identity Persistence với HMAC signing
- Anti-tampering + Anti-copy protection

**Tasks**:
- [x] 11.6.1 Create HWID module (CPU ID, BIOS Serial, Machine GUID) ✅ (2025-12-12)
- [x] 11.6.2 Create Identity Storage với HMAC-SHA256 signing ✅ (2025-12-12)
- [x] 11.6.3 Integrate Identity Manager into Cloud Sync ✅ (2025-12-12)
- [x] 11.6.4 Test: Agent restart uses same ID ✅ (2025-12-12)
- [ ] 11.6.5 Add Cloud verify_identity endpoint (anti-rollback)
- [ ] 11.6.6 Add DPAPI encryption (optional Windows-native)

---

### 11.4 Compliance Reports

**ISO 27001 Controls to cover**:
- A.12.4.1 - Event Logging
- A.12.4.3 - Administrator/Operator Logs
- A.16.1.2 - Reporting Information Security Events
- A.16.1.4 - Assessment of Events
- A.16.1.5 - Response to Incidents

**Tasks**:
- [ ] 11.4.1 Create report data models
- [ ] 11.4.2 Generate A.12.4.1 report (Event Logging)
- [ ] 11.4.3 Generate A.16.1.x reports (Incidents)
- [ ] 11.4.4 PDF export functionality
- [ ] 11.4.5 Scheduled report generation

---

### 11.5 UI/UX Design

**Design System**:
- Dark mode (primary)
- Glassmorphism cards
- Responsive (Desktop + Tablet)
- Charts: Chart.js or Recharts

**Pages**:
| Page | Description | Priority |
|------|-------------|----------|
| Login | Email/password auth | 🔴 High |
| Dashboard | Overview stats | 🔴 High |
| Agents | List all endpoints | 🔴 High |
| Agent Detail | Single agent view | 🟡 Medium |
| Incidents | All incidents | 🔴 High |
| Incident Detail | Timeline + actions | 🟡 Medium |
| Policies | Manage policies | 🟡 Medium |
| Reports | Generate reports | 🟢 Low |

---

## 📊 Priority Matrix

| Task | Effort | Impact | Priority |
|------|--------|--------|----------|
| Login + Auth | Low | High | 🔴 1 |
| Dashboard Stats | Medium | High | 🔴 2 |
| Agents List | Low | High | 🔴 3 |
| Incidents List | Low | High | 🔴 4 |
| Real-time Updates | High | Medium | 🟡 5 |
| Policies | Medium | Medium | 🟡 6 |
| Reports | High | Medium | 🟢 7 |

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| Frontend | React + Vite |
| Styling | CSS + Glassmorphism |
| Charts | Chart.js / Recharts |
| API Client | fetch / axios |
| Auth | JWT |
| Real-time | WebSocket |
| Backend | Axum (existing) |
| Database | PostgreSQL (existing) |

---

## 📅 Estimated Timeline

| Day | Tasks |
|-----|-------|
| 1 | Setup React project + Login page |
| 2 | Dashboard + Agents list |
| 3 | Incidents list + detail |
| 4 | Policies + WebSocket |
| 5 | Reports + Polish |

---

## 🔗 Dependencies

**Trước khi bắt đầu Phase 11, đảm bảo**:

- [x] Phase 10 complete (Cloud Backend)
- [x] Agent registration working
- [x] Heartbeat sync working
- [x] Incident auto-sync working
- [x] Cloud Status UI working
- [x] Test full flow end-to-end (Verified 2025-12-12)

---

## 📝 Notes

- Sử dụng lại design system từ Tauri app (Glassmorphism)
- API đã có sẵn trong cloud-server
- Focus vào MVP trước, sau đó polish

**Start command**:
```bash
# Create React app
cd cloud-server
mkdir dashboard
cd dashboard
npx create-vite@latest . --template react
npm install
npm run dev
```

---

**Created by**: AI Assistant
**Last Updated**: 2025-12-12
