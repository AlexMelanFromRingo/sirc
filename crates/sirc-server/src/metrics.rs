//! Performance metrics tracking for SIRC federation
//!
//! Tracks server performance, network health, and routing statistics

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Performance metrics for the federation server
#[derive(Debug, Clone)]
pub struct ServerMetrics {
    /// Server start time
    pub start_time: Instant,

    /// Total messages sent
    pub messages_sent: u64,

    /// Total messages received
    pub messages_received: u64,

    /// Total encrypted messages
    pub encrypted_messages: u64,

    /// Active peer connections
    pub active_connections: usize,

    /// Total connections established
    pub total_connections: u64,

    /// Failed connection attempts
    pub failed_connections: u64,

    /// Messages routed through this server
    pub messages_routed: u64,

    /// Network partitions detected
    pub partitions_detected: u64,

    /// Partitions healed
    pub partitions_healed: u64,

    /// Average message latency (ms)
    pub avg_latency_ms: f64,

    /// Minimum message latency (ms)
    pub min_latency_ms: f64,

    /// Maximum message latency (ms)
    pub max_latency_ms: f64,

    /// TLS handshakes successful
    pub tls_handshakes_success: u64,

    /// TLS handshakes failed
    pub tls_handshakes_failed: u64,

    /// Reconnection attempts
    pub reconnection_attempts: u64,

    /// Successful reconnections
    pub reconnections_successful: u64,
}

impl ServerMetrics {
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn connection_success_rate(&self) -> f64 {
        if self.total_connections == 0 {
            return 0.0;
        }
        (self.total_connections as f64 / (self.total_connections + self.failed_connections) as f64) * 100.0
    }

    pub fn tls_success_rate(&self) -> f64 {
        let total = self.tls_handshakes_success + self.tls_handshakes_failed;
        if total == 0 {
            return 0.0;
        }
        (self.tls_handshakes_success as f64 / total as f64) * 100.0
    }

    pub fn reconnection_success_rate(&self) -> f64 {
        if self.reconnection_attempts == 0 {
            return 0.0;
        }
        (self.reconnections_successful as f64 / self.reconnection_attempts as f64) * 100.0
    }
}

/// Atomic metrics collector for concurrent access
pub struct MetricsCollector {
    start_time: Instant,
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    encrypted_messages: AtomicU64,
    active_connections: AtomicUsize,
    total_connections: AtomicU64,
    failed_connections: AtomicU64,
    messages_routed: AtomicU64,
    partitions_detected: AtomicU64,
    partitions_healed: AtomicU64,
    tls_handshakes_success: AtomicU64,
    tls_handshakes_failed: AtomicU64,
    reconnection_attempts: AtomicU64,
    reconnections_successful: AtomicU64,
    latency_stats: Arc<RwLock<LatencyStats>>,
}

#[derive(Debug, Clone)]
struct LatencyStats {
    samples: Vec<f64>,
    max_samples: usize,
}

impl LatencyStats {
    fn new(max_samples: usize) -> Self {
        Self {
            samples: Vec::with_capacity(max_samples),
            max_samples,
        }
    }

    fn add_sample(&mut self, latency_ms: f64) {
        if self.samples.len() >= self.max_samples {
            self.samples.remove(0);
        }
        self.samples.push(latency_ms);
    }

    fn avg(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.samples.iter().sum::<f64>() / self.samples.len() as f64
    }

    fn min(&self) -> f64 {
        self.samples.iter().cloned().fold(f64::INFINITY, f64::min)
    }

    fn max(&self) -> f64 {
        self.samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
    }
}

impl MetricsCollector {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            start_time: Instant::now(),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            encrypted_messages: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
            total_connections: AtomicU64::new(0),
            failed_connections: AtomicU64::new(0),
            messages_routed: AtomicU64::new(0),
            partitions_detected: AtomicU64::new(0),
            partitions_healed: AtomicU64::new(0),
            tls_handshakes_success: AtomicU64::new(0),
            tls_handshakes_failed: AtomicU64::new(0),
            reconnection_attempts: AtomicU64::new(0),
            reconnections_successful: AtomicU64::new(0),
            latency_stats: Arc::new(RwLock::new(LatencyStats::new(1000))),
        })
    }

    pub fn increment_messages_sent(&self) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_messages_received(&self) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_encrypted_messages(&self) {
        self.encrypted_messages.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_active_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_active_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn increment_failed_connections(&self) {
        self.failed_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_messages_routed(&self) {
        self.messages_routed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_partitions_detected(&self) {
        self.partitions_detected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_partitions_healed(&self) {
        self.partitions_healed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_tls_success(&self) {
        self.tls_handshakes_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_tls_failed(&self) {
        self.tls_handshakes_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_reconnection_attempt(&self) {
        self.reconnection_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_reconnection_success(&self) {
        self.reconnections_successful.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn record_latency(&self, latency_ms: f64) {
        let mut stats = self.latency_stats.write().await;
        stats.add_sample(latency_ms);
    }

    pub async fn snapshot(&self) -> ServerMetrics {
        let latency_stats = self.latency_stats.read().await;

        ServerMetrics {
            start_time: self.start_time,
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            encrypted_messages: self.encrypted_messages.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_connections: self.total_connections.load(Ordering::Relaxed),
            failed_connections: self.failed_connections.load(Ordering::Relaxed),
            messages_routed: self.messages_routed.load(Ordering::Relaxed),
            partitions_detected: self.partitions_detected.load(Ordering::Relaxed),
            partitions_healed: self.partitions_healed.load(Ordering::Relaxed),
            avg_latency_ms: latency_stats.avg(),
            min_latency_ms: latency_stats.min(),
            max_latency_ms: latency_stats.max(),
            tls_handshakes_success: self.tls_handshakes_success.load(Ordering::Relaxed),
            tls_handshakes_failed: self.tls_handshakes_failed.load(Ordering::Relaxed),
            reconnection_attempts: self.reconnection_attempts.load(Ordering::Relaxed),
            reconnections_successful: self.reconnections_successful.load(Ordering::Relaxed),
        }
    }

    pub async fn print_summary(&self) {
        let metrics = self.snapshot().await;

        println!("\n┌─────────────────────────────────────────────────────────┐");
        println!("│          SIRC Server Performance Metrics                │");
        println!("├─────────────────────────────────────────────────────────┤");
        println!("│ Uptime: {:?}", metrics.uptime());
        println!("├─────────────────────────────────────────────────────────┤");
        println!("│ Messages:                                                │");
        println!("│   Sent:      {:>10}                                │", metrics.messages_sent);
        println!("│   Received:  {:>10}                                │", metrics.messages_received);
        println!("│   Encrypted: {:>10}                                │", metrics.encrypted_messages);
        println!("│   Routed:    {:>10}                                │", metrics.messages_routed);
        println!("├─────────────────────────────────────────────────────────┤");
        println!("│ Connections:                                             │");
        println!("│   Active:    {:>10}                                │", metrics.active_connections);
        println!("│   Total:     {:>10}                                │", metrics.total_connections);
        println!("│   Failed:    {:>10}                                │", metrics.failed_connections);
        println!("│   Success:   {:>9.1}%                                │", metrics.connection_success_rate());
        println!("├─────────────────────────────────────────────────────────┤");
        println!("│ TLS:                                                     │");
        println!("│   Success:   {:>10}                                │", metrics.tls_handshakes_success);
        println!("│   Failed:    {:>10}                                │", metrics.tls_handshakes_failed);
        println!("│   Success:   {:>9.1}%                                │", metrics.tls_success_rate());
        println!("├─────────────────────────────────────────────────────────┤");
        println!("│ Reconnections:                                           │");
        println!("│   Attempts:  {:>10}                                │", metrics.reconnection_attempts);
        println!("│   Success:   {:>10}                                │", metrics.reconnections_successful);
        println!("│   Rate:      {:>9.1}%                                │", metrics.reconnection_success_rate());
        println!("├─────────────────────────────────────────────────────────┤");
        println!("│ Network Partitions:                                      │");
        println!("│   Detected:  {:>10}                                │", metrics.partitions_detected);
        println!("│   Healed:    {:>10}                                │", metrics.partitions_healed);
        println!("├─────────────────────────────────────────────────────────┤");
        println!("│ Message Latency (ms):                                    │");
        println!("│   Average:   {:>10.2}                                │", metrics.avg_latency_ms);
        println!("│   Minimum:   {:>10.2}                                │", metrics.min_latency_ms);
        println!("│   Maximum:   {:>10.2}                                │", metrics.max_latency_ms);
        println!("└─────────────────────────────────────────────────────────┘\n");
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self {
            start_time: Instant::now(),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            encrypted_messages: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
            total_connections: AtomicU64::new(0),
            failed_connections: AtomicU64::new(0),
            messages_routed: AtomicU64::new(0),
            partitions_detected: AtomicU64::new(0),
            partitions_healed: AtomicU64::new(0),
            tls_handshakes_success: AtomicU64::new(0),
            tls_handshakes_failed: AtomicU64::new(0),
            reconnection_attempts: AtomicU64::new(0),
            reconnections_successful: AtomicU64::new(0),
            latency_stats: Arc::new(RwLock::new(LatencyStats::new(1000))),
        }
    }
}
