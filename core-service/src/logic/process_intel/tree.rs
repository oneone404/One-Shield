//! Process Tree Module - Phân tích Parent-Child Relationships (Phase 2)
//!
//! Mục đích: Xây dựng và phân tích process tree để phát hiện:
//! - Suspicious parent-child relationships
//! - Deep process chains
//! - Orphaned processes

use std::collections::HashMap;
use parking_lot::RwLock;
use once_cell::sync::Lazy;

use super::types::{ProcessInfo, ProcessTreeNode, TreeAnalysisResult, SuspiciousChain, SpawnSeverity, SignatureStatus};

// ============================================================================
// STATE
// ============================================================================

static PROCESS_TREE: Lazy<RwLock<ProcessTree>> = Lazy::new(|| RwLock::new(ProcessTree::new()));

// ============================================================================
// PROCESS TREE STRUCT
// ============================================================================

pub struct ProcessTree {
    nodes: HashMap<u32, ProcessTreeNode>,
    roots: Vec<u32>,  // PIDs of root processes (no parent)
    last_update: i64,
}

impl ProcessTree {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            roots: Vec::new(),
            last_update: 0,
        }
    }
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Lấy node theo PID
pub fn get_node(pid: u32) -> Option<ProcessTreeNode> {
    PROCESS_TREE.read().nodes.get(&pid).cloned()
}

/// Lấy thông tin process
pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    PROCESS_TREE.read().nodes.get(&pid).map(|n| n.info.clone())
}

/// Lấy parent của process
pub fn get_process_parent(pid: u32) -> Option<ProcessInfo> {
    let tree = PROCESS_TREE.read();
    if let Some(node) = tree.nodes.get(&pid) {
        if let Some(parent_pid) = node.info.parent_pid {
            return tree.nodes.get(&parent_pid).map(|n| n.info.clone());
        }
    }
    None
}

/// Lấy children của process
pub fn get_children(pid: u32) -> Vec<ProcessInfo> {
    let tree = PROCESS_TREE.read();
    if let Some(node) = tree.nodes.get(&pid) {
        node.children
            .iter()
            .filter_map(|&child_pid| tree.nodes.get(&child_pid))
            .map(|n| n.info.clone())
            .collect()
    } else {
        Vec::new()
    }
}

/// Lấy toàn bộ process tree hiện tại
pub fn get_process_tree() -> HashMap<u32, ProcessTreeNode> {
    PROCESS_TREE.read().nodes.clone()
}

/// Refresh process tree từ system
pub fn refresh_tree() {
    use sysinfo::System;

    let system = System::new_all();
    let mut tree = PROCESS_TREE.write();
    tree.nodes.clear();
    tree.roots.clear();

    // First pass: collect all processes
    for (pid, process) in system.processes() {
        let pid_u32 = pid.as_u32();
        let parent_pid = process.parent().map(|p| p.as_u32());

        let exe_path = process.exe().map(|p| p.to_path_buf());

        let info = ProcessInfo {
            pid: pid_u32,
            name: process.name().to_string(),
            exe_path,
            cmdline: Some(process.cmd().join(" ")),
            parent_pid,
            parent_name: None, // Will be filled in second pass
            start_time: process.start_time() as i64,
            signature: SignatureStatus::Unsigned, // Will be verified on demand
            user: None,
            session_id: None,
        };

        let node = ProcessTreeNode {
            info,
            children: Vec::new(),
            depth: 0,
        };

        tree.nodes.insert(pid_u32, node);
    }

    // Second pass: build parent-child relationships and find roots
    let pids: Vec<u32> = tree.nodes.keys().copied().collect();

    for pid in pids {
        let parent_pid = tree.nodes.get(&pid).and_then(|n| n.info.parent_pid);

        if let Some(parent_pid) = parent_pid {
            // Check if parent exists
            if tree.nodes.contains_key(&parent_pid) {
                // Add this as child of parent
                if let Some(parent_node) = tree.nodes.get_mut(&parent_pid) {
                    parent_node.children.push(pid);
                }

                // Set parent name
                let parent_name = tree.nodes.get(&parent_pid).map(|n| n.info.name.clone());
                if let Some(node) = tree.nodes.get_mut(&pid) {
                    node.info.parent_name = parent_name;
                }
            } else {
                // Parent doesn't exist, this is a root
                tree.roots.push(pid);
            }
        } else {
            // No parent, this is a root
            tree.roots.push(pid);
        }
    }

    // Third pass: calculate depths
    calculate_depths(&mut tree);

    tree.last_update = chrono::Utc::now().timestamp();
}

/// Tính depths cho tất cả nodes
fn calculate_depths(tree: &mut ProcessTree) {
    fn set_depth(tree: &mut ProcessTree, pid: u32, depth: u32) {
        if let Some(node) = tree.nodes.get_mut(&pid) {
            node.depth = depth;
            let children: Vec<u32> = node.children.clone();
            for child in children {
                set_depth(tree, child, depth + 1);
            }
        }
    }

    let roots = tree.roots.clone();
    for root in roots {
        set_depth(tree, root, 0);
    }
}

/// Lấy chain từ pid đến root
pub fn get_ancestry_chain(pid: u32) -> Vec<ProcessInfo> {
    let tree = PROCESS_TREE.read();
    let mut chain = Vec::new();
    let mut current = Some(pid);

    while let Some(current_pid) = current {
        if let Some(node) = tree.nodes.get(&current_pid) {
            chain.push(node.info.clone());
            current = node.info.parent_pid;

            // Prevent infinite loop
            if chain.len() > 100 {
                break;
            }
        } else {
            break;
        }
    }

    chain
}

/// Lấy tất cả descendants của một process
pub fn get_descendants(pid: u32) -> Vec<ProcessInfo> {
    let tree = PROCESS_TREE.read();
    let mut descendants = Vec::new();

    fn collect_descendants(tree: &ProcessTree, pid: u32, result: &mut Vec<ProcessInfo>) {
        if let Some(node) = tree.nodes.get(&pid) {
            for &child_pid in &node.children {
                if let Some(child_node) = tree.nodes.get(&child_pid) {
                    result.push(child_node.info.clone());
                    collect_descendants(tree, child_pid, result);
                }
            }
        }
    }

    collect_descendants(&tree, pid, &mut descendants);
    descendants
}

/// Phân tích tree từ một PID
pub fn analyze_subtree(pid: u32) -> TreeAnalysisResult {
    let tree = PROCESS_TREE.read();

    let descendants = {
        let mut d = Vec::new();
        fn collect(tree: &ProcessTree, pid: u32, result: &mut Vec<ProcessInfo>) {
            if let Some(node) = tree.nodes.get(&pid) {
                for &child_pid in &node.children {
                    if let Some(child_node) = tree.nodes.get(&child_pid) {
                        result.push(child_node.info.clone());
                        collect(tree, child_pid, result);
                    }
                }
            }
        }
        collect(&tree, pid, &mut d);
        d
    };

    let max_depth = descendants.iter()
        .filter_map(|p| tree.nodes.get(&p.pid))
        .map(|n| n.depth)
        .max()
        .unwrap_or(0);

    let suspicious_chains = find_suspicious_chains_for_pid(&tree, pid);

    TreeAnalysisResult {
        root_pid: pid,
        total_descendants: descendants.len(),
        max_depth,
        suspicious_chains,
    }
}

/// Tìm các suspicious chains trong subtree
fn find_suspicious_chains_for_pid(tree: &ProcessTree, pid: u32) -> Vec<SuspiciousChain> {
    let mut chains = Vec::new();

    // Get chain from root to pid
    let chain = {
        let mut chain = Vec::new();
        let mut current = Some(pid);

        while let Some(current_pid) = current {
            if let Some(node) = tree.nodes.get(&current_pid) {
                chain.push(node.info.clone());
                current = node.info.parent_pid;
            } else {
                break;
            }
        }

        chain.reverse();
        chain
    };

    // Check for suspicious patterns
    for i in 0..chain.len().saturating_sub(1) {
        let parent = &chain[i];
        let child = &chain[i + 1];

        if let Some(alert) = check_spawn_pattern(parent, child) {
            chains.push(SuspiciousChain {
                chain: chain[0..=i+1].to_vec(),
                reason: alert.0,
                severity: alert.1,
            });
        }
    }

    chains
}

/// Kiểm tra pattern spawn giữa parent-child
fn check_spawn_pattern(parent: &ProcessInfo, child: &ProcessInfo) -> Option<(String, SpawnSeverity)> {
    let parent_name = parent.name.to_lowercase();
    let child_name = child.name.to_lowercase();

    // Office spawning shell
    if (parent_name.contains("winword") || parent_name.contains("excel") ||
        parent_name.contains("powerpnt") || parent_name.contains("outlook")) &&
       (child_name == "cmd.exe" || child_name == "powershell.exe" ||
        child_name == "wscript.exe" || child_name == "cscript.exe") {
        return Some((
            format!("{} spawned {}", parent.name, child.name),
            SpawnSeverity::High,
        ));
    }

    // Explorer spawning suspicious
    if parent_name == "explorer.exe" &&
       (child_name == "mshta.exe" || child_name == "wscript.exe" || child_name == "regsvr32.exe") {
        return Some((
            format!("Explorer spawned suspicious: {}", child.name),
            SpawnSeverity::Medium,
        ));
    }

    // Browser spawning shell
    if (parent_name.contains("chrome") || parent_name.contains("firefox") ||
        parent_name.contains("edge") || parent_name.contains("iexplore")) &&
       (child_name == "cmd.exe" || child_name == "powershell.exe") {
        return Some((
            format!("Browser {} spawned {}", parent.name, child.name),
            SpawnSeverity::High,
        ));
    }

    None
}

// ============================================================================
// STATISTICS
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct TreeStats {
    pub total_processes: usize,
    pub root_processes: usize,
    pub max_depth: u32,
    pub avg_children: f32,
    pub last_update: i64,
}

pub fn get_stats() -> TreeStats {
    let tree = PROCESS_TREE.read();

    let max_depth = tree.nodes.values().map(|n| n.depth).max().unwrap_or(0);
    let total_children: usize = tree.nodes.values().map(|n| n.children.len()).sum();
    let avg_children = if tree.nodes.is_empty() {
        0.0
    } else {
        total_children as f32 / tree.nodes.len() as f32
    };

    TreeStats {
        total_processes: tree.nodes.len(),
        root_processes: tree.roots.len(),
        max_depth,
        avg_children,
        last_update: tree.last_update,
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_spawn_pattern() {
        let parent = ProcessInfo::new(1000, "WINWORD.EXE".to_string());
        let child = ProcessInfo::new(2000, "cmd.exe".to_string());

        let result = check_spawn_pattern(&parent, &child);
        assert!(result.is_some());

        if let Some((_, severity)) = result {
            assert_eq!(severity, SpawnSeverity::High);
        }
    }

    #[test]
    fn test_normal_spawn() {
        let parent = ProcessInfo::new(1000, "explorer.exe".to_string());
        let child = ProcessInfo::new(2000, "notepad.exe".to_string());

        let result = check_spawn_pattern(&parent, &child);
        assert!(result.is_none());
    }
}
