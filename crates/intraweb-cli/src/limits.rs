//! Limits on what strangers can make this node do.
//!
//! Anyone within radio range can reach the mail endpoint, and identities are
//! free to mint -- so a per-sender limit alone buys nothing, because a flooder
//! simply uses a fresh key each time. Every check therefore passes a global
//! bucket as well, which is the one that actually bounds the damage.

use intraweb_core::PeerId;
use std::collections::HashMap;
use std::sync::Mutex;

/// Messages a single peer may burst before it has to slow down.
pub const PER_PEER_BURST: f64 = 20.0;
/// Sustained rate for one peer: roughly twelve a minute.
pub const PER_PEER_REFILL_PER_SEC: f64 = 0.2;

/// Burst across everyone at once.
pub const GLOBAL_BURST: f64 = 120.0;
/// Sustained rate across the whole network: about two a second.
pub const GLOBAL_REFILL_PER_SEC: f64 = 2.0;

/// Cap on remembered senders, so minting keys cannot grow this map forever.
const MAX_TRACKED_PEERS: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    updated_at: f64,
}

impl Bucket {
    fn new(capacity: f64, now: f64) -> Self {
        Self {
            tokens: capacity,
            updated_at: now,
        }
    }

    /// Refill for elapsed time, then spend one token if there is one.
    fn take(&mut self, capacity: f64, refill_per_sec: f64, now: f64) -> bool {
        let elapsed = (now - self.updated_at).max(0.0);
        self.tokens = (self.tokens + elapsed * refill_per_sec).min(capacity);
        self.updated_at = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct RateLimiter {
    per_peer: Mutex<HashMap<PeerId, Bucket>>,
    global: Mutex<Bucket>,
}

impl RateLimiter {
    pub fn new(now: f64) -> Self {
        Self {
            per_peer: Mutex::new(HashMap::new()),
            global: Mutex::new(Bucket::new(GLOBAL_BURST, now)),
        }
    }

    /// Whether to accept one more message from this peer right now.
    ///
    /// The global bucket is checked first and unconditionally: it is the only
    /// limit a flooder cannot sidestep by generating new identities.
    pub fn allow(&self, peer_id: PeerId, now: f64) -> bool {
        {
            let Ok(mut global) = self.global.lock() else {
                return false;
            };
            if !global.take(GLOBAL_BURST, GLOBAL_REFILL_PER_SEC, now) {
                return false;
            }
        }

        let Ok(mut buckets) = self.per_peer.lock() else {
            return false;
        };

        // Drop senders whose buckets have long since refilled; they carry no
        // information and would otherwise accumulate for every key ever seen.
        if buckets.len() >= MAX_TRACKED_PEERS {
            let full_again = PER_PEER_BURST / PER_PEER_REFILL_PER_SEC;
            buckets.retain(|_, bucket| now - bucket.updated_at < full_again);
            // Still full of live senders: refuse rather than grow without limit.
            if buckets.len() >= MAX_TRACKED_PEERS {
                return false;
            }
        }

        buckets
            .entry(peer_id)
            .or_insert_with(|| Bucket::new(PER_PEER_BURST, now))
            .take(PER_PEER_BURST, PER_PEER_REFILL_PER_SEC, now)
    }

    /// How many senders are currently remembered. Used to prove the map stays
    /// bounded under a key-minting flood.
    #[cfg(test)]
    pub fn tracked_peers(&self) -> usize {
        self.per_peer.lock().map(|b| b.len()).unwrap_or(0)
    }
}

/// Seconds as a float, for the buckets above.
pub fn now_float() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use intraweb_core::Identity;

    fn peer() -> PeerId {
        Identity::generate().unwrap().peer_id()
    }

    #[test]
    fn ordinary_use_is_never_throttled() {
        let limiter = RateLimiter::new(0.0);
        let alice = peer();
        // A few messages while writing to somebody: nowhere near a limit.
        for i in 0..5 {
            assert!(
                limiter.allow(alice, i as f64 * 2.0),
                "message {i} should pass"
            );
        }
    }

    #[test]
    fn one_peer_flooding_is_cut_off() {
        let limiter = RateLimiter::new(0.0);
        let mallory = peer();
        let accepted = (0..200).filter(|_| limiter.allow(mallory, 0.0)).count();

        assert_eq!(
            accepted, PER_PEER_BURST as usize,
            "only the burst gets through"
        );
    }

    #[test]
    fn a_throttled_peer_recovers_with_time() {
        let limiter = RateLimiter::new(0.0);
        let mallory = peer();
        while limiter.allow(mallory, 0.0) {}

        assert!(!limiter.allow(mallory, 0.0));
        // Five seconds buys one token back at the sustained rate.
        assert!(
            limiter.allow(mallory, 5.0),
            "the limit is a slowdown, not a ban"
        );
    }

    #[test]
    fn minting_fresh_keys_does_not_sidestep_the_limit() {
        // The attack a per-sender limit alone would miss entirely.
        let limiter = RateLimiter::new(0.0);
        let accepted = (0..500).filter(|_| limiter.allow(peer(), 0.0)).count();

        assert_eq!(
            accepted, GLOBAL_BURST as usize,
            "the global bucket bounds it"
        );
    }

    #[test]
    fn one_peer_cannot_starve_everybody_else() {
        let limiter = RateLimiter::new(0.0);
        let mallory = peer();
        let alice = peer();

        // Mallory burns their own allowance.
        while limiter.allow(mallory, 0.0) {}

        // Alice, arriving after, still gets through on the shared budget.
        assert!(limiter.allow(alice, 0.0));
    }

    #[test]
    fn tracked_senders_do_not_grow_without_bound() {
        let limiter = RateLimiter::new(0.0);
        // Far more distinct keys than the cap, spread over time so the global
        // bucket keeps refilling and the per-peer map is what is under test.
        for i in 0..(MAX_TRACKED_PEERS + 500) {
            limiter.allow(peer(), i as f64);
        }
        assert!(
            limiter.tracked_peers() <= MAX_TRACKED_PEERS,
            "an attacker minting keys must not grow the map forever",
        );
    }
}
