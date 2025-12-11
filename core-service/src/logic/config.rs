#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, Ordering};

// FREEZE CORE: Safety Configuration (Kill-switches)
// Default state: All systems nominal (Enabled)
static AI_ENABLED: AtomicBool = AtomicBool::new(true);
static EXPLAIN_ENABLED: AtomicBool = AtomicBool::new(true);
static AUTO_BLOCK_ENABLED: AtomicBool = AtomicBool::new(true);
static REALTIME_LEARNING: AtomicBool = AtomicBool::new(true);

pub struct SafetyConfig;

impl SafetyConfig {
    pub fn is_ai_enabled() -> bool {
        AI_ENABLED.load(Ordering::Relaxed)
    }

    pub fn is_explain_enabled() -> bool {
        EXPLAIN_ENABLED.load(Ordering::Relaxed)
    }

    pub fn is_auto_block_enabled() -> bool {
        AUTO_BLOCK_ENABLED.load(Ordering::Relaxed)
    }

    pub fn is_learning_enabled() -> bool {
        REALTIME_LEARNING.load(Ordering::Relaxed)
    }

    // Setters (e.g. from Emergency UI or Panic Handler)
    pub fn set_ai(val: bool) { AI_ENABLED.store(val, Ordering::Relaxed); }
    pub fn set_explain(val: bool) { EXPLAIN_ENABLED.store(val, Ordering::Relaxed); }
    pub fn set_auto_block(val: bool) { AUTO_BLOCK_ENABLED.store(val, Ordering::Relaxed); }
    pub fn set_learning(val: bool) { REALTIME_LEARNING.store(val, Ordering::Relaxed); }
}
