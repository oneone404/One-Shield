# 🎨 PHASE 15 — UI/UX REDESIGN & OPTIMIZATION

*Refactor giao diện AI Security App cho UX tối ưu*

---

## 🎯 GOAL

Sau Phase 15:
- ✅ Layout tabs logic, dễ navigate
- ✅ Mỗi tab có mục đích rõ ràng
- ✅ Không có thông tin thừa/lẫn lộn
- ✅ Flow từ Overview → Details → Actions
- ✅ Professional AI Security look & feel

---

## 📊 CURRENT STATE (Before)

### Sidebar hiện tại (8 tabs):
```
1. Dashboard     - Mixed: Stats + AI Engine + Incidents + Threats
2. Executive     - Executive summary (OK)
3. Monitoring    - ⚠️ Placeholder
4. Alerts        - ⚠️ Placeholder
5. Processes     - ⚠️ Placeholder
6. Logs          - ⚠️ Placeholder
7. Training Data - ⚠️ Placeholder
8. Settings      - Quarantine + Webhooks + Account (OK)
```

### Vấn đề:
- Dashboard quá nhiều components (7+)
- 5/8 tabs là placeholder
- Thiếu tab cho Threats/Detections chuyên biệt
- Training Data ít dùng, không nên nổi bật

---

## 🎯 TARGET STATE (After)

### Sidebar mới (6 tabs):
```
1. 🏠 Overview      - System health + Quick stats
2. 🛡️ Threats       - Incidents + Detection alerts (CORE)
3. 📊 Analytics     - Charts + Executive insights
4. ⚙️ Processes     - Live process list + Monitoring
5. 📋 Logs          - Security logs + History
6. ⚙️ Settings      - Config + Account + Webhooks
```

---

## 📐 15.1 — SIDEBAR RESTRUCTURE

### 15.1.1 New Menu Items
| ID | Label | Icon | Purpose |
|----|-------|------|---------|
| overview | Overview | `Home` | System health quick view |
| threats | Threats | `Shield` / `AlertTriangle` | **Incidents + Detections** |
| analytics | Analytics | `BarChart3` | Charts, Executive, AI Status |
| processes | Processes | `Cpu` | Live process monitoring |
| logs | Logs | `FileText` | Security log viewer |
| settings | Settings | `Settings` | Config, Account, Webhooks |

### Tasks:
- [ ] Update `Sidebar.jsx` menuItems
- [ ] Remove unused tabs (monitoring, alerts, data, executive)
- [ ] Add new tab routing in `App.jsx`

---

## 📐 15.2 — OVERVIEW TAB (Home)

**Purpose**: Quick system health at a glance

### Layout:
```
┌─────────────────────────────────────────────────┐
│ SYSTEM STATUS                    [Cloud: ✅]   │
├──────────┬──────────┬──────────┬───────────────┤
│ CPU Card │ Memory   │ Network  │ Processes     │
│  45%     │  68%     │ ↑50KB/s  │ 125 running   │
├──────────┴──────────┴──────────┴───────────────┤
│ AI ENGINE STATUS                               │
│ ┌─────────────────────────────────────────────┐│
│ │ Model: ONNX v2.0 ✅  |  Baseline: Stable    ││
│ │ Samples: 290         |  Threats: 0 today    ││
│ └─────────────────────────────────────────────┘│
├────────────────────────────────────────────────┤
│ RECENT ACTIVITY (3-5 items)                    │
│ • 12:05 - System scan completed                │
│ • 11:32 - Anomaly detected in chrome.exe       │
│ • 10:15 - Baseline updated                     │
└────────────────────────────────────────────────┘
```

### Components:
- [ ] SystemStatCards (CPU, Memory, Network, Processes)
- [ ] AiEngineStatus (compact version)
- [ ] RecentActivityFeed (new component)
- [ ] CloudStatus indicator

### Tasks:
- [ ] Create `OverviewPage.jsx`
- [ ] Move stat cards from Dashboard
- [ ] Create compact `AiEngineStatusCompact.jsx`
- [ ] Create `RecentActivityFeed.jsx`
- [ ] Remove GPU card (move to Analytics)

---

## 📐 15.3 — THREATS TAB (Core Feature)

**Purpose**: All security detections in one place

### Layout:
```
┌─────────────────────────────────────────────────┐
│ THREAT SUMMARY                                  │
│ ┌─────────┬─────────┬─────────┬───────────────┐│
│ │ Active  │ Today   │ Week    │ Severity      ││
│ │ 2       │ 5       │ 23      │ 🔴 2 Critical ││
│ └─────────┴─────────┴─────────┴───────────────┘│
├────────────────────────────────────────────────┤
│ ACTIVE INCIDENTS                               │
│ ┌─────────────────────────────────────────────┐│
│ │ [List of IncidentPanel items]               ││
│ └─────────────────────────────────────────────┘│
├────────────────────────────────────────────────┤
│ DETECTION ALERTS                               │
│ ┌─────────────────────────────────────────────┐│
│ │ [ThreatAlertPanel - advanced detections]    ││
│ │ - Process Injection detected                 ││
│ │ - Suspicious script blocked                  ││
│ │ - Keylogger pattern detected                 ││
│ └─────────────────────────────────────────────┘│
└────────────────────────────────────────────────┘
```

### Components:
- [ ] ThreatSummaryCards (new)
- [ ] IncidentPanel (from Dashboard)
- [ ] ThreatAlertPanel (from Dashboard)
- [ ] ThreatDetailsModal (for drill-down)

### Tasks:
- [ ] Create `ThreatsPage.jsx`
- [ ] Move IncidentPanel from Dashboard
- [ ] Move ThreatAlertPanel from Dashboard
- [ ] Create `ThreatSummaryCards.jsx`
- [ ] Add filtering: severity, date range, type

---

## 📐 15.4 — ANALYTICS TAB

**Purpose**: Charts, trends, executive insights

### Layout:
```
┌─────────────────────────────────────────────────┐
│ SECURITY SCORE                    Period: 7d ▼ │
│ ┌─────────────────────────────────────────────┐│
│ │      [ 87 ]  GOOD                           ││
│ │      Security Health Score                   ││
│ └─────────────────────────────────────────────┘│
├──────────────────────┬─────────────────────────┤
│ SYSTEM USAGE CHART   │ THREAT TREND            │
│ [CPU/Memory graph]   │ [Incidents over time]   │
├──────────────────────┴─────────────────────────┤
│ AI ENGINE DETAILS                              │
│ ┌─────────────────────────────────────────────┐│
│ │ [Full AiEngineStatus with dataset info]     ││
│ └─────────────────────────────────────────────┘│
├────────────────────────────────────────────────┤
│ EXECUTIVE SUMMARY                              │
│ [ExecutiveDashboard content - endpoints, etc]  │
└────────────────────────────────────────────────┘
```

### Components:
- [ ] SecurityScoreCard (new - from Executive)
- [ ] UsageChart (from Dashboard)
- [ ] ThreatTrendChart (new)
- [ ] AiEngineStatus (full version)
- [ ] ExecutiveSummary (simplified)
- [ ] GpuCard (moved here)

### Tasks:
- [ ] Create `AnalyticsPage.jsx`
- [ ] Move UsageChart from Dashboard
- [ ] Move AiEngineStatus (full) here
- [ ] Create `SecurityScoreCard.jsx`
- [ ] Create `ThreatTrendChart.jsx`
- [ ] Merge ExecutiveDashboard content

---

## 📐 15.5 — PROCESSES TAB

**Purpose**: Live process monitoring

### Layout:
```
┌─────────────────────────────────────────────────┐
│ RUNNING PROCESSES              [Search] [Filter]│
├─────────────────────────────────────────────────┤
│ ┌───────────────────────────────────────────────┐
│ │ PID  │ Name         │ CPU │ Memory │ Status  │
│ ├──────┼──────────────┼─────┼────────┼─────────┤
│ │ 1234 │ chrome.exe   │ 12% │ 450MB  │ 🟢      │
│ │ 5678 │ node.exe     │ 8%  │ 120MB  │ ⚠️ Spike │
│ │ ...  │ ...          │ ... │ ...    │ ...     │
│ └───────────────────────────────────────────────┘
├─────────────────────────────────────────────────┤
│ ACTIONS: [Kill] [Suspend] [Add to Whitelist]   │
└─────────────────────────────────────────────────┘
```

### Components:
- [ ] ProcessTable (new - sortable, filterable)
- [ ] ProcessActions (kill, suspend, whitelist)
- [ ] ProcessDetailsModal

### Tasks:
- [ ] Create `ProcessesPage.jsx`
- [ ] Create `ProcessTable.jsx` component
- [ ] Add sorting by CPU, Memory, Name
- [ ] Add filtering (system, user, spikes only)
- [ ] Add process actions

---

## 📐 15.6 — LOGS TAB

**Purpose**: Security log history viewer

### Layout:
```
┌─────────────────────────────────────────────────┐
│ SECURITY LOGS              Date: [Dec 14] ▼    │
├─────────────────────────────────────────────────┤
│ [Search...] [Filter: All ▼] [Export]           │
├─────────────────────────────────────────────────┤
│ ┌───────────────────────────────────────────────┐
│ │ 12:05:32 │ SCAN │ Completed system scan      │
│ │ 11:45:10 │ WARN │ High CPU spike detected    │
│ │ 11:32:05 │ THREAT│ Process injection blocked │
│ │ 11:15:00 │ INFO │ Baseline updated           │
│ │ ...      │ ...  │ ...                        │
│ └───────────────────────────────────────────────┘
├─────────────────────────────────────────────────┤
│ Showing 50 of 1,234 entries   [< 1 2 3 ... >]  │
└─────────────────────────────────────────────────┘
```

### Components:
- [ ] SecurityLogs (existing - enhanced)
- [ ] LogFilter (date, type, severity)
- [ ] LogExport (JSON, CSV)

### Tasks:
- [ ] Create `LogsPage.jsx`
- [ ] Enhance SecurityLogs component
- [ ] Add date picker filter
- [ ] Add log type filter
- [ ] Add export functionality
- [ ] Add pagination

---

## 📐 15.7 — SETTINGS TAB (Existing - Enhance)

**Purpose**: Configuration & Account

### Sections:
1. **Account** - User info, tier, logout
2. **Quarantine** - Quarantined files management
3. **Webhooks** - Notification integrations
4. **Preferences** - Theme, language, etc.
5. **About** - Version, system info

### Tasks:
- [ ] Keep existing Settings page
- [ ] Add Preferences section (theme, language)
- [ ] Add About section with version info
- [ ] Improve layout/grouping

---

## 📊 PROGRESS SUMMARY

| Section | Status | Priority |
|---------|--------|----------|
| 15.1 Sidebar Restructure | ⏳ Not Started | 🔴 HIGH |
| 15.2 Overview Tab | ⏳ Not Started | 🔴 HIGH |
| 15.3 Threats Tab | ⏳ Not Started | 🔴 HIGH |
| 15.4 Analytics Tab | ⏳ Not Started | 🟡 MEDIUM |
| 15.5 Processes Tab | ⏳ Not Started | 🟡 MEDIUM |
| 15.6 Logs Tab | ⏳ Not Started | 🟡 MEDIUM |
| 15.7 Settings Enhancement | ⏳ Not Started | 🟢 LOW |

**Overall Phase 15 Progress: 0%**

---

## 🔄 MIGRATION STRATEGY

### Step 1: Create new pages without breaking existing
1. Create `OverviewPage.jsx`
2. Create `ThreatsPage.jsx`
3. Create `AnalyticsPage.jsx`
4. Create `ProcessesPage.jsx`
5. Create `LogsPage.jsx`

### Step 2: Update routing
1. Update `App.jsx` renderPage()
2. Update `Sidebar.jsx` menuItems

### Step 3: Move components
1. Move cards to appropriate pages
2. Remove components from Dashboard
3. Delete old placeholder code

### Step 4: Polish & Test
1. Ensure all pages work
2. Test navigation
3. Update styles

---

## 🎯 Definition of Done

Phase 15 is complete when:

- [ ] 6-tab sidebar (Overview, Threats, Analytics, Processes, Logs, Settings)
- [ ] Each tab has dedicated content (no placeholders)
- [ ] Dashboard components moved to appropriate tabs
- [ ] Clean navigation flow
- [ ] Consistent styling across all pages
- [ ] Mobile-friendly layout

---

## 🚀 Next Actions

1. **Start with 15.1** - Update Sidebar structure
2. **Then 15.2** - Create Overview page
3. **Then 15.3** - Create Threats page (most important)

---

*Created: 2025-12-14 19:05*
*Last Updated: 2025-12-14 19:05*
