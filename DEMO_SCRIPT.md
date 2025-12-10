# One-Shield v1.0 Demo Script (5-7 Mins)

## 1. Intro (1 min)
- **Hook**: "Traditional AVs fail against 0-day attacks. We built One-Shield to detect behavior, not hashes."
- **Dashboard**: Show the main dashboard. Highlight "System Normal" status.
- **Glassmorphism**: Point out the modern, professional UI (EDR vibe).

## 2. The Baseline (1 min)
- **Action**: Leave the system idle.
- **Explain**: "Right now, the AI is observing normal behavior. CPU is low, Network is quiet."
- **Show**: "Dataset Inspector" -> Benign samples increasing.

## 3. Attack Simulation (Simulated) (2 mins)
- **Action**: Run a simulated stress test (or describe the scenario).
- **Scenario**: "Imagine a Crypto-miner infection." (Process consumes 80% CPU).
- **Reaction**:
    - **Incident Panel**: A new "Critical" incident appears immediately.
    - **Notification**: "Anomaly Detected: Unusual CPU Pattern".

## 4. Investigation & Explanation (2 mins)
- **Action**: Click on the Incident in the Timeline.
- **Show**: The **"Why detected?"** section.
- **Highlight**:
    - "Look here: 'Anomalous CPU Usage Patterns'."
    - "And here: 'Process Churn Rate' is high."
    - "This explains exactly WHY the AI triggered, without needing a data scientist."

## 5. Defense & Training (1 min)
- **Action**: Click "Export Dataset".
- **Explain**: "This data is now saved. We can feed it back to our Offline Trainer to make the model smarter next time (Closed-loop AI)."
- **Close**: "One-Shield isn't just a tool, it's an evolving defense system."

---
*Tip: Keep the flow smooth. Don't debug on demo.*
