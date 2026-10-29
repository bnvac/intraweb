//! What this node has actually sent and received, measured where it happens.
//!
//! Deliberately local. A shared "network speed" would mean every node
//! broadcasting its numbers to every other, which is replication this project
//! does not do, and the number would be fiction anyway: throughput is a
//! property of a pair of machines and the path between them, not of the
//! neighborhood. What one node can honestly report is what it saw.
//!
//! Latency and throughput are kept apart for the same reason. A short post
//! takes as long as a round trip whatever the link can carry, so timing one
//! and dividing would report a "speed" that only measures distance.

use serde::Serialize;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Exchanges remembered for the rolling figures.
const RECENT: usize = 64;

/// Below this, an exchange is all round trip and says nothing about bandwidth.
pub const THROUGHPUT_FLOOR_BYTES: u64 = 32 * 1024;

static BYTES_OUT: AtomicU64 = AtomicU64::new(0);
static BYTES_IN: AtomicU64 = AtomicU64::new(0);
static EXCHANGES: AtomicU64 = AtomicU64::new(0);
static FAILURES: AtomicU64 = AtomicU64::new(0);
static RECENT_LOG: Mutex<VecDeque<Exchange>> = Mutex::new(VecDeque::new());

#[derive(Debug, Clone, Copy)]
struct Exchange {
    at: u64,
    bytes: u64,
    millis: u64,
    outbound: bool,
}

/// Which way the bytes went, from this node's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// We dialled a peer.
    Out,
    /// A peer dialled us.
    In,
}

/// Note one completed exchange with a peer.
pub fn record(direction: Direction, sent: u64, received: u64, took: Duration) {
    BYTES_OUT.fetch_add(sent, Ordering::Relaxed);
    BYTES_IN.fetch_add(received, Ordering::Relaxed);
    EXCHANGES.fetch_add(1, Ordering::Relaxed);

    let exchange = Exchange {
        at: intraweb_core::peer::now_secs(),
        bytes: sent + received,
        millis: u64::try_from(took.as_millis()).unwrap_or(u64::MAX).max(1),
        outbound: direction == Direction::Out,
    };
    if let Ok(mut log) = RECENT_LOG.lock() {
        if log.len() == RECENT {
            log.pop_front();
        }
        log.push_back(exchange);
    }
}

/// Note a peer we could not reach, which is half of what "connection is bad"
/// means and is not visible from the byte counts alone.
pub fn record_failure() {
    FAILURES.fetch_add(1, Ordering::Relaxed);
}

/// Whether traffic from this address is a neighbor's, rather than the
/// operator's own dashboard polling every couple of seconds.
pub fn is_neighbor(addr: IpAddr) -> bool {
    !addr.is_loopback()
}

#[derive(Debug, Serialize)]
pub struct Activity {
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub exchanges: u64,
    pub failures: u64,
    /// Median time for one of our recent outbound exchanges to complete.
    /// `None` until we have dialled somebody.
    pub latency_ms: Option<u64>,
    /// Bytes per second over recent exchanges big enough to measure it.
    /// `None` until one has happened; a guess would be worse than nothing.
    pub throughput_bps: Option<u64>,
    /// When the most recent exchange finished, in Unix seconds.
    pub last_exchange_at: Option<u64>,
}

pub fn snapshot() -> Activity {
    let log: Vec<Exchange> = RECENT_LOG
        .lock()
        .map(|log| log.iter().copied().collect())
        .unwrap_or_default();
    summarise(
        &log,
        BYTES_OUT.load(Ordering::Relaxed),
        BYTES_IN.load(Ordering::Relaxed),
        EXCHANGES.load(Ordering::Relaxed),
        FAILURES.load(Ordering::Relaxed),
    )
}

fn summarise(
    log: &[Exchange],
    bytes_out: u64,
    bytes_in: u64,
    exchanges: u64,
    failures: u64,
) -> Activity {
    let mut round_trips: Vec<u64> = log
        .iter()
        .filter(|e| e.outbound)
        .map(|e| e.millis)
        .collect();
    round_trips.sort_unstable();
    let latency_ms = round_trips.get(round_trips.len() / 2).copied();

    // Outbound only: those are timed to the last byte. A file we serve is
    // timed by the server only until its headers are ready, while the body is
    // still streaming, so counting it would flatter the link.
    let (big_bytes, big_millis) = log
        .iter()
        .filter(|e| e.outbound && e.bytes >= THROUGHPUT_FLOOR_BYTES)
        .fold((0u64, 0u64), |(bytes, millis), e| {
            (bytes + e.bytes, millis + e.millis)
        });
    let throughput_bps = (big_millis > 0).then(|| big_bytes.saturating_mul(1000) / big_millis);

    Activity {
        bytes_out,
        bytes_in,
        exchanges,
        failures,
        latency_ms,
        throughput_bps,
        last_exchange_at: log.last().map(|e| e.at),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(bytes: u64, millis: u64, outbound: bool) -> Exchange {
        Exchange {
            at: 1,
            bytes,
            millis,
            outbound,
        }
    }

    #[test]
    fn nothing_measured_reports_nothing_rather_than_zero() {
        let activity = summarise(&[], 0, 0, 0, 0);
        assert_eq!(activity.latency_ms, None);
        assert_eq!(activity.throughput_bps, None);
    }

    /// A tiny post over a slow round trip must not read as a slow link.
    #[test]
    fn small_exchanges_never_count_as_throughput() {
        let log = [exchange(400, 200, true), exchange(900, 150, true)];
        let activity = summarise(&log, 1300, 0, 2, 0);
        assert_eq!(activity.throughput_bps, None);
        assert_eq!(activity.latency_ms, Some(200), "the median of 150 and 200");
    }

    #[test]
    fn throughput_comes_from_transfers_big_enough_to_measure() {
        let log = [
            exchange(1_000_000, 1000, true),
            exchange(3_000_000, 1000, true),
            exchange(500, 900, true),
        ];
        let activity = summarise(&log, 0, 0, 3, 0);
        assert_eq!(activity.throughput_bps, Some(2_000_000));
    }

    /// Served files are timed only until their headers are ready, so they
    /// would make the link look faster than it is.
    #[test]
    fn what_we_serve_counts_toward_totals_but_not_speed() {
        let log = [exchange(5_000_000, 3, false)];
        let activity = summarise(&log, 5_000_000, 0, 1, 0);
        assert_eq!(activity.throughput_bps, None);
        assert_eq!(activity.latency_ms, None);
    }

    #[test]
    fn the_dashboard_on_this_machine_is_not_a_neighbor() {
        assert!(!is_neighbor("127.0.0.1".parse().unwrap()));
        assert!(!is_neighbor("::1".parse().unwrap()));
        assert!(is_neighbor("192.168.1.20".parse().unwrap()));
    }
}
