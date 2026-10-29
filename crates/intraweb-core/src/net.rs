//! Nets: open groups of channels with a leader the members can replace.
//!
//! There is no server to hold a net's state, so a net *is* its log. Every act
//! -- founding it, joining, opening a motion, voting, setting policy,
//! announcing -- is a signed post in the net's governance channel, and each
//! node folds the log it holds into the same answer. Two nodes with the same
//! posts agree on who leads without asking each other; a node that was away
//! catches up through ordinary channel backfill and then agrees too.
//!
//! What this cannot do is stop a determined cheat. A net is open, and keys
//! are free, so anyone can join with a hundred. The defence that keeps it
//! open is that a motion names who may vote on it when it is opened: keys
//! minted after a vote begins count for nothing. Keys minted *before*, by
//! somebody planning ahead, still count. That is the honest limit of a
//! majority vote among strangers, and the dashboard says so.

use crate::channel::ChannelId;
use crate::hex;
use crate::identity::PeerId;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const NET_LABEL: &[u8] = b"intraweb-net-v1";
const GOVERNANCE_LABEL: &[u8] = b"intraweb-net-governance-v1";
const GENERAL_LABEL: &[u8] = b"intraweb-net-general-v1";

/// Longest net name, matching channel names.
pub const MAX_NET_NAME: usize = 40;
/// Longest announcement.
pub const MAX_ANNOUNCEMENT: usize = 500;
/// How many members a motion can name as voters. Each is a 16-hex key prefix,
/// which keeps the motion inside one post; grinding a key to match a 64-bit
/// prefix of somebody else's is not a practical attack.
pub const MAX_ELIGIBLE: usize = 300;
/// A motion nobody carries in a day is closed, so an old one cannot be
/// revived at three in the morning by whoever is still awake.
pub const MOTION_LIFETIME_SECS: u64 = 24 * 60 * 60;
/// A ping wakes everybody, so the leader gets one per ten minutes. More are
/// still shown, just without the ping.
pub const PING_INTERVAL_SECS: u64 = 10 * 60;

/// Identifies a net. Derived from the founder's key and a nonce, so a charter
/// proves its own founder: nobody can republish it under their own name.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct NetId([u8; 32]);

impl NetId {
    pub fn derive(founder: PeerId, nonce: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(NET_LABEL);
        hasher.update(founder.as_bytes());
        hasher.update(nonce.as_bytes());
        Self(hasher.finalize().into())
    }

    /// A fresh net id for this founder, with the nonce that proves it.
    pub fn found(founder: PeerId) -> Result<(Self, String)> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|e| anyhow::anyhow!("could not read entropy for a net id: {e}"))?;
        let nonce = hex::encode(&bytes);
        Ok((Self::derive(founder, &nonce), nonce))
    }

    /// Where the net's log lives.
    pub fn governance(&self) -> ChannelId {
        ChannelId::derived(GOVERNANCE_LABEL, &self.0)
    }

    /// The net's open conversation, which every member is in.
    pub fn general(&self) -> ChannelId {
        ChannelId::derived(GENERAL_LABEL, &self.0)
    }

    pub fn to_hex(self) -> String {
        hex::encode(&self.0)
    }

    pub fn parse_hex(s: &str) -> Option<Self> {
        hex::decode_array::<32>(s).map(Self)
    }
}

impl Serialize for NetId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for NetId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid net id"))
    }
}

/// The short form a motion uses to name voters.
pub fn short_key(peer: PeerId) -> String {
    peer.to_hex().chars().take(16).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MotionKind {
    /// Replace the leader. Any member may open one.
    Impeach,
    /// Remove a member. Only the leader may open one, and the members decide.
    Kick,
}

/// One act in a net, carried as the body of a post in its governance channel.
///
/// Every event names its net, and one naming a different net from the channel
/// it arrived in is ignored -- otherwise a vote could be lifted from one net
/// and replayed in another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Charter {
        net: NetId,
        name: String,
        nonce: String,
    },
    Join {
        net: NetId,
    },
    Leave {
        net: NetId,
    },
    Motion {
        net: NetId,
        id: String,
        kind: MotionKind,
        target: PeerId,
        /// Who may vote, fixed when the motion opens.
        eligible: Vec<String>,
    },
    Vote {
        net: NetId,
        motion: String,
        yes: bool,
    },
    Policy {
        net: NetId,
        low_data_mandatory: bool,
    },
    Announce {
        net: NetId,
        text: String,
        ping: bool,
    },
}

impl Event {
    pub fn net(&self) -> NetId {
        match self {
            Event::Charter { net, .. }
            | Event::Join { net }
            | Event::Leave { net }
            | Event::Motion { net, .. }
            | Event::Vote { net, .. }
            | Event::Policy { net, .. }
            | Event::Announce { net, .. } => *net,
        }
    }

    /// Checks that do not need the log: what any honest node would refuse to
    /// even send.
    pub fn check(&self) -> Result<()> {
        match self {
            Event::Charter { name, .. } => {
                ensure!(!name.trim().is_empty(), "a net needs a name");
                ensure!(
                    name.chars().count() <= MAX_NET_NAME,
                    "that name is too long"
                );
            }
            Event::Motion { id, eligible, .. } => {
                ensure!(
                    id.len() == 16 && hex::decode_array::<8>(id).is_some(),
                    "bad motion id"
                );
                ensure!(
                    eligible.len() <= MAX_ELIGIBLE,
                    "a vote can name at most {MAX_ELIGIBLE} members"
                );
            }
            Event::Announce { text, .. } => {
                ensure!(!text.trim().is_empty(), "nothing to announce");
                ensure!(
                    text.chars().count() <= MAX_ANNOUNCEMENT,
                    "an announcement is limited to {MAX_ANNOUNCEMENT} characters"
                );
            }
            _ => {}
        }
        Ok(())
    }
}

/// A fresh motion id.
pub fn new_motion_id() -> Result<String> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes)
        .map_err(|e| anyhow::anyhow!("could not read entropy for a motion: {e}"))?;
    Ok(hex::encode(&bytes))
}

/// One verified entry in a net's log: the event, who signed it, when they say
/// they did, and the signature, which breaks ties and seeds succession.
#[derive(Debug, Clone)]
pub struct Entry {
    pub from: PeerId,
    pub at: u64,
    pub signature: String,
    pub event: Event,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Member {
    pub peer_id: PeerId,
    pub joined_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MotionStatus {
    Open,
    Passed,
    Failed,
    Expired,
}

#[derive(Debug, Clone, Serialize)]
pub struct MotionState {
    pub id: String,
    pub kind: MotionKind,
    pub target: PeerId,
    pub opened_by: PeerId,
    pub opened_at: u64,
    pub closes_at: u64,
    pub eligible: usize,
    pub yes: usize,
    pub no: usize,
    pub status: MotionStatus,
    /// Latest vote of each voter.
    pub votes: Vec<(PeerId, bool)>,
    /// For an impeachment that passed, who leads now.
    pub successor: Option<PeerId>,
    /// Why it closed, in words a person can read.
    pub outcome: Option<String>,
    #[serde(skip)]
    eligible_keys: Vec<String>,
    #[serde(skip)]
    yes_signatures: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Announcement {
    pub at: u64,
    pub from: PeerId,
    pub text: String,
    pub ping: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub at: u64,
    pub text: String,
}

/// Everything a net is, as of the log folded so far.
#[derive(Debug, Clone, Serialize)]
pub struct NetState {
    pub net: NetId,
    pub name: Option<String>,
    pub founder: Option<PeerId>,
    pub leader: Option<PeerId>,
    /// Longest-standing first.
    pub members: Vec<Member>,
    pub banned: Vec<PeerId>,
    pub low_data_mandatory: bool,
    pub motions: Vec<MotionState>,
    pub announcements: Vec<Announcement>,
    /// What happened, for people to read.
    pub history: Vec<Record>,
}

impl NetState {
    pub fn is_member(&self, peer: PeerId) -> bool {
        self.members.iter().any(|m| m.peer_id == peer)
    }

    /// Members as a motion names them.
    pub fn eligible_now(&self) -> Vec<String> {
        self.members
            .iter()
            .take(MAX_ELIGIBLE)
            .map(|m| short_key(m.peer_id))
            .collect()
    }
}

/// Fold a net's log into its state.
///
/// Order is by the time each author signed, then by signature, so every node
/// holding the same entries sees the same sequence whatever order they arrived
/// in. `now` only decides which open motions have run out of time.
pub fn fold(net: NetId, mut entries: Vec<Entry>, now: u64) -> NetState {
    // Clocks are only roughly right, and a second is coarse, so time alone
    // does not order a log causally. The founding charter goes first whatever
    // its timestamp -- nothing in a net can precede the net -- and within one
    // second a join comes before a motion, which comes before a vote. Before
    // this, a join signed in the same second as the charter could sort ahead
    // of it and be thrown away. (Real bug, named regression test.)
    let founding = entries
        .iter()
        .filter(|e| match &e.event {
            Event::Charter { net: id, nonce, .. } => {
                *id == net && NetId::derive(e.from, nonce) == net
            }
            _ => false,
        })
        .min_by(|a, b| a.at.cmp(&b.at).then_with(|| a.signature.cmp(&b.signature)))
        .map(|e| e.signature.clone());
    entries.sort_by(|a, b| {
        let a_founds = founding.as_ref() == Some(&a.signature);
        let b_founds = founding.as_ref() == Some(&b.signature);
        b_founds
            .cmp(&a_founds)
            .then_with(|| a.at.cmp(&b.at))
            .then_with(|| rank(&a.event).cmp(&rank(&b.event)))
            .then_with(|| a.signature.cmp(&b.signature))
    });
    // Votes for a motion the fold has not reached yet. A voter whose clock
    // runs behind the mover's signs a vote that sorts before the motion; it is
    // held here and counted when the motion opens, so a slow clock does not
    // cost anybody their vote.
    let mut waiting: std::collections::HashMap<String, Vec<(PeerId, bool, String, u64)>> =
        std::collections::HashMap::new();

    let mut state = NetState {
        net,
        name: None,
        founder: None,
        leader: None,
        members: Vec::new(),
        banned: Vec::new(),
        low_data_mandatory: false,
        motions: Vec::new(),
        announcements: Vec::new(),
        history: Vec::new(),
    };
    let mut last_ping: Option<u64> = None;

    for entry in entries {
        if entry.event.net() != net || entry.event.check().is_err() {
            continue;
        }
        if state.banned.contains(&entry.from) {
            continue;
        }
        // Expire first, so a vote arriving after the deadline cannot carry it.
        expire(&mut state, entry.at);

        match &entry.event {
            Event::Charter { name, nonce, .. } => {
                // Only the first charter, and only one whose id its author
                // can prove: the id is derived from the founder's key.
                if state.founder.is_some() || NetId::derive(entry.from, nonce) != net {
                    continue;
                }
                state.founder = Some(entry.from);
                state.name = Some(name.trim().to_string());
                state.leader = Some(entry.from);
                state.members.push(Member {
                    peer_id: entry.from,
                    joined_at: entry.at,
                });
                note(
                    &mut state,
                    entry.at,
                    format!("{} founded the net", short(entry.from)),
                );
            }
            // Nothing counts before the net exists.
            _ if state.founder.is_none() => {}
            Event::Join { .. } => {
                if state.is_member(entry.from) {
                    continue;
                }
                state.members.push(Member {
                    peer_id: entry.from,
                    joined_at: entry.at,
                });
                // A net whose leader left with nobody behind gets the next
                // person through the door.
                if state.leader.is_none() {
                    state.leader = Some(entry.from);
                    note(
                        &mut state,
                        entry.at,
                        format!("{} leads, as the only member", short(entry.from)),
                    );
                }
            }
            Event::Leave { .. } => {
                if !state.is_member(entry.from) {
                    continue;
                }
                state.members.retain(|m| m.peer_id != entry.from);
                if state.leader == Some(entry.from) {
                    // Whoever has been here longest takes over.
                    state.leader = state.members.first().map(|m| m.peer_id);
                    let text = match state.leader {
                        Some(next) => format!(
                            "{} left; {} has been here longest and leads now",
                            short(entry.from),
                            short(next)
                        ),
                        None => format!("{} left; the net has nobody in it", short(entry.from)),
                    };
                    note(&mut state, entry.at, text);
                }
            }
            Event::Motion {
                id,
                kind,
                target,
                eligible,
                ..
            } => {
                if !state.is_member(entry.from) || state.motions.iter().any(|m| &m.id == id) {
                    continue;
                }
                let allowed = match kind {
                    MotionKind::Impeach => state.leader == Some(*target),
                    MotionKind::Kick => {
                        state.leader == Some(entry.from)
                            && *target != entry.from
                            && state.is_member(*target)
                    }
                };
                let already_open = state.motions.iter().any(|m| {
                    m.status == MotionStatus::Open && m.kind == *kind && m.target == *target
                });
                if !allowed || already_open {
                    continue;
                }
                // Only names that are members right now; a motion cannot
                // smuggle in voters the net never had.
                let current: Vec<String> =
                    state.members.iter().map(|m| short_key(m.peer_id)).collect();
                let mut eligible_keys: Vec<String> = eligible
                    .iter()
                    .filter(|k| current.contains(k))
                    .cloned()
                    .collect();
                eligible_keys.sort();
                eligible_keys.dedup();
                if eligible_keys.is_empty() {
                    continue;
                }
                state.motions.push(MotionState {
                    id: id.clone(),
                    kind: *kind,
                    target: *target,
                    opened_by: entry.from,
                    opened_at: entry.at,
                    closes_at: entry.at + MOTION_LIFETIME_SECS,
                    eligible: eligible_keys.len(),
                    yes: 0,
                    no: 0,
                    status: MotionStatus::Open,
                    votes: Vec::new(),
                    successor: None,
                    outcome: None,
                    eligible_keys,
                    yes_signatures: Vec::new(),
                });
                let verb = match kind {
                    MotionKind::Impeach => "moved to impeach",
                    MotionKind::Kick => "called a vote to remove",
                };
                note(
                    &mut state,
                    entry.at,
                    format!("{} {verb} {}", short(entry.from), short(*target)),
                );
                // Opening a motion is a vote for it.
                cast(&mut state, id, entry.from, true, &entry.signature, entry.at);
                for (voter, yes, signature, at) in waiting.remove(id).unwrap_or_default() {
                    cast(&mut state, id, voter, yes, &signature, at);
                }
            }
            Event::Vote { motion, yes, .. } => {
                if state.motions.iter().any(|m| &m.id == motion) {
                    cast(
                        &mut state,
                        motion,
                        entry.from,
                        *yes,
                        &entry.signature,
                        entry.at,
                    );
                } else {
                    waiting.entry(motion.clone()).or_default().push((
                        entry.from,
                        *yes,
                        entry.signature.clone(),
                        entry.at,
                    ));
                }
            }
            Event::Policy {
                low_data_mandatory, ..
            } => {
                if state.leader != Some(entry.from)
                    || state.low_data_mandatory == *low_data_mandatory
                {
                    continue;
                }
                state.low_data_mandatory = *low_data_mandatory;
                note(
                    &mut state,
                    entry.at,
                    if *low_data_mandatory {
                        "the leader made low data mode mandatory: no pictures or files".into()
                    } else {
                        "the leader lifted mandatory low data mode".into()
                    },
                );
            }
            Event::Announce { text, ping, .. } => {
                if state.leader != Some(entry.from) {
                    continue;
                }
                let ping =
                    *ping && last_ping.is_none_or(|last| entry.at >= last + PING_INTERVAL_SECS);
                if ping {
                    last_ping = Some(entry.at);
                }
                state.announcements.push(Announcement {
                    at: entry.at,
                    from: entry.from,
                    text: text.trim().to_string(),
                    ping,
                });
            }
        }
    }
    expire(&mut state, now);
    state
}

/// Causal order within one second: a net before its members, members before
/// motions, motions before votes on them.
fn rank(event: &Event) -> u8 {
    match event {
        Event::Charter { .. } => 0,
        Event::Join { .. } => 1,
        Event::Motion { .. } => 2,
        Event::Vote { .. } => 3,
        _ => 4,
    }
}

fn short(peer: PeerId) -> String {
    peer.fingerprint().chars().take(9).collect()
}

fn note(state: &mut NetState, at: u64, text: String) {
    state.history.push(Record { at, text });
}

fn expire(state: &mut NetState, now: u64) {
    for motion in &mut state.motions {
        if motion.status == MotionStatus::Open && now > motion.closes_at {
            motion.status = MotionStatus::Expired;
            motion.outcome = Some("ran out of time without a majority".into());
        }
    }
}

/// Record a vote and settle the motion if it now has a majority either way.
fn cast(state: &mut NetState, motion_id: &str, voter: PeerId, yes: bool, signature: &str, at: u64) {
    let Some(index) = state.motions.iter().position(|m| m.id == motion_id) else {
        return;
    };
    {
        let motion = &mut state.motions[index];
        if motion.status != MotionStatus::Open || !motion.eligible_keys.contains(&short_key(voter))
        {
            return;
        }
        if !state.members.iter().any(|m| m.peer_id == voter) {
            return;
        }
        // A changed mind replaces the earlier vote.
        motion.votes.retain(|(who, _)| *who != voter);
        motion.votes.push((voter, yes));
        motion.yes = motion.votes.iter().filter(|(_, v)| *v).count();
        motion.no = motion.votes.len() - motion.yes;
        if yes {
            motion.yes_signatures.push(signature.to_string());
        }
    }

    let motion = state.motions[index].clone();
    // A strict majority of everyone who may vote, not of who bothered to.
    let half = motion.eligible / 2;
    if motion.no > half {
        let m = &mut state.motions[index];
        m.status = MotionStatus::Failed;
        m.outcome = Some("a majority voted against".into());
        return;
    }
    if motion.yes <= half {
        return;
    }

    match motion.kind {
        MotionKind::Impeach => {
            if state.leader != Some(motion.target) {
                let m = &mut state.motions[index];
                m.status = MotionStatus::Failed;
                m.outcome = Some("they were no longer leading".into());
                return;
            }
            let mut candidates: Vec<PeerId> = state
                .members
                .iter()
                .map(|m| m.peer_id)
                .filter(|p| *p != motion.target)
                .collect();
            if candidates.is_empty() {
                let m = &mut state.motions[index];
                m.status = MotionStatus::Failed;
                m.outcome = Some("there is nobody else to lead".into());
                return;
            }
            candidates.sort_by_key(|p| p.to_hex());
            // Random, but the same everywhere: seeded by the votes that
            // carried it, which nobody could know in advance and every node
            // holding the log can recompute.
            let mut hasher = Sha256::new();
            hasher.update(motion.id.as_bytes());
            for signature in &motion.yes_signatures {
                hasher.update(signature.as_bytes());
            }
            let seed = hasher.finalize();
            let mut first = [0u8; 8];
            first.copy_from_slice(&seed[..8]);
            let pick = candidates[(u64::from_le_bytes(first) % candidates.len() as u64) as usize];

            state.leader = Some(pick);
            let m = &mut state.motions[index];
            m.status = MotionStatus::Passed;
            m.successor = Some(pick);
            m.outcome = Some(format!("passed; {} was drawn to lead", short(pick)));
            note(
                state,
                at,
                format!(
                    "{} was impeached; {} was drawn to lead",
                    short(motion.target),
                    short(pick)
                ),
            );
        }
        MotionKind::Kick => {
            state.members.retain(|m| m.peer_id != motion.target);
            state.banned.push(motion.target);
            let m = &mut state.motions[index];
            m.status = MotionStatus::Passed;
            m.outcome = Some("passed; they were removed".into());
            note(
                state,
                at,
                format!("the members voted {} out", short(motion.target)),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    struct Net {
        id: NetId,
        log: Vec<Entry>,
        clock: u64,
    }

    impl Net {
        fn founded_by(founder: &Identity) -> Self {
            let (id, nonce) = NetId::found(founder.peer_id()).unwrap();
            let mut net = Net {
                id,
                log: Vec::new(),
                clock: 1000,
            };
            net.act(
                founder,
                Event::Charter {
                    net: id,
                    name: "basecamp".into(),
                    nonce,
                },
            );
            net
        }

        fn act(&mut self, who: &Identity, event: Event) {
            self.clock += 10;
            self.at(who, event, self.clock);
        }

        fn at(&mut self, who: &Identity, event: Event, at: u64) {
            self.log.push(Entry {
                from: who.peer_id(),
                at,
                // Distinct and unpredictable, like a real one.
                signature: hex::encode(&who.sign(format!("{at}{event:?}").as_bytes())),
                event,
            });
        }

        fn join(&mut self, who: &Identity) {
            self.act(who, Event::Join { net: self.id });
        }

        fn state(&self) -> NetState {
            fold(self.id, self.log.clone(), self.clock)
        }

        fn motion(&mut self, who: &Identity, kind: MotionKind, target: PeerId) -> String {
            let id = new_motion_id().unwrap();
            let eligible = self.state().eligible_now();
            self.act(
                who,
                Event::Motion {
                    net: self.id,
                    id: id.clone(),
                    kind,
                    target,
                    eligible,
                },
            );
            id
        }

        fn vote(&mut self, who: &Identity, motion: &str, yes: bool) {
            self.act(
                who,
                Event::Vote {
                    net: self.id,
                    motion: motion.into(),
                    yes,
                },
            );
        }
    }

    fn people(n: usize) -> Vec<Identity> {
        (0..n).map(|_| Identity::generate().unwrap()).collect()
    }

    #[test]
    fn the_founder_leads_a_new_net() {
        let p = people(1);
        let net = Net::founded_by(&p[0]);
        let state = net.state();
        assert_eq!(state.leader, Some(p[0].peer_id()));
        assert_eq!(state.name.as_deref(), Some("basecamp"));
        assert!(state.is_member(p[0].peer_id()));
    }

    /// The id is derived from the founder's key, so a copied charter proves
    /// nothing: a squatter cannot claim somebody else's net.
    #[test]
    fn a_charter_is_only_valid_from_the_key_it_was_derived_for() {
        let p = people(2);
        let (id, nonce) = NetId::found(p[0].peer_id()).unwrap();
        let mut net = Net {
            id,
            log: Vec::new(),
            clock: 1000,
        };
        // The squatter gets in first, with the real nonce.
        net.at(
            &p[1],
            Event::Charter {
                net: id,
                name: "mine now".into(),
                nonce: nonce.clone(),
            },
            900,
        );
        net.act(
            &p[0],
            Event::Charter {
                net: id,
                name: "basecamp".into(),
                nonce,
            },
        );
        let state = net.state();
        assert_eq!(state.founder, Some(p[0].peer_id()));
        assert_eq!(state.name.as_deref(), Some("basecamp"));
    }

    fn entry(who: &Identity, at: u64, signature: &str, event: Event) -> Entry {
        Entry {
            from: who.peer_id(),
            at,
            signature: signature.into(),
            event,
        }
    }

    /// Regression: a join signed in the same second as the charter, whose
    /// signature happened to sort first, was folded before the net existed
    /// and thrown away. Found as an intermittent test failure.
    #[test]
    fn a_join_in_the_same_second_as_the_charter_still_counts() {
        let p = people(2);
        let (net, nonce) = NetId::found(p[0].peer_id()).unwrap();
        let log = vec![
            entry(&p[1], 500, "00", Event::Join { net }),
            entry(
                &p[0],
                500,
                "ff",
                Event::Charter {
                    net,
                    name: "basecamp".into(),
                    nonce,
                },
            ),
        ];
        assert!(fold(net, log, 600).is_member(p[1].peer_id()));
    }

    /// A voter whose clock runs behind the mover's signs a vote dated before
    /// the motion. It must still count.
    #[test]
    fn a_vote_from_a_slow_clock_is_not_lost() {
        let p = people(3);
        let (net, nonce) = NetId::found(p[0].peer_id()).unwrap();
        let eligible: Vec<String> = p.iter().map(|x| short_key(x.peer_id())).collect();
        let log = vec![
            entry(
                &p[0],
                100,
                "a1",
                Event::Charter {
                    net,
                    name: "basecamp".into(),
                    nonce,
                },
            ),
            entry(&p[1], 110, "a2", Event::Join { net }),
            entry(&p[2], 120, "a3", Event::Join { net }),
            entry(
                &p[1],
                200,
                "a4",
                Event::Motion {
                    net,
                    id: "0123456789abcdef".into(),
                    kind: MotionKind::Impeach,
                    target: p[0].peer_id(),
                    eligible,
                },
            ),
            // Carol's clock is a minute slow.
            entry(
                &p[2],
                140,
                "a5",
                Event::Vote {
                    net,
                    motion: "0123456789abcdef".into(),
                    yes: true,
                },
            ),
        ];
        let state = fold(net, log, 300);
        assert_eq!(state.motions[0].status, MotionStatus::Passed);
        assert_ne!(state.leader, Some(p[0].peer_id()));
    }

    #[test]
    fn when_the_leader_leaves_the_longest_standing_member_leads() {
        let p = people(3);
        let mut net = Net::founded_by(&p[0]);
        net.join(&p[1]);
        net.join(&p[2]);
        net.act(&p[0], Event::Leave { net: net.id });
        assert_eq!(net.state().leader, Some(p[1].peer_id()));
    }

    #[test]
    fn a_majority_impeaches_and_somebody_else_is_drawn_to_lead() {
        let p = people(4);
        let mut net = Net::founded_by(&p[0]);
        for who in &p[1..] {
            net.join(who);
        }
        let motion = net.motion(&p[1], MotionKind::Impeach, p[0].peer_id());
        net.vote(&p[2], &motion, true);
        assert_eq!(
            net.state().leader,
            Some(p[0].peer_id()),
            "two of four is not a majority"
        );
        net.vote(&p[3], &motion, true);

        let state = net.state();
        let leader = state.leader.unwrap();
        assert_ne!(leader, p[0].peer_id());
        assert!(state.is_member(leader));
        assert_eq!(state.motions[0].status, MotionStatus::Passed);
        assert_eq!(state.motions[0].successor, Some(leader));
    }

    /// Every node must draw the same successor, whatever order the posts
    /// reached it in.
    #[test]
    fn every_node_draws_the_same_successor() {
        let p = people(5);
        let mut net = Net::founded_by(&p[0]);
        for who in &p[1..] {
            net.join(who);
        }
        let motion = net.motion(&p[1], MotionKind::Impeach, p[0].peer_id());
        net.vote(&p[2], &motion, true);
        net.vote(&p[3], &motion, true);

        let mut shuffled = net.log.clone();
        shuffled.reverse();
        let a = net.state().leader;
        let b = fold(net.id, shuffled, net.clock).leader;
        assert_eq!(a, b);
    }

    /// The point of naming voters when a motion opens: keys minted afterwards
    /// to swing it count for nothing.
    #[test]
    fn keys_that_join_after_a_vote_opens_cannot_swing_it() {
        let p = people(3);
        let mut net = Net::founded_by(&p[0]);
        net.join(&p[1]);
        net.join(&p[2]);
        let motion = net.motion(&p[1], MotionKind::Impeach, p[0].peer_id());

        let sybils = people(5);
        for s in &sybils {
            net.join(s);
            net.vote(s, &motion, true);
        }
        let state = net.state();
        assert_eq!(state.leader, Some(p[0].peer_id()));
        assert_eq!(state.motions[0].yes, 1, "only the mover's vote counts");
    }

    #[test]
    fn a_motion_cannot_name_voters_who_are_not_members() {
        let p = people(2);
        let outsiders = people(3);
        let mut net = Net::founded_by(&p[0]);
        net.join(&p[1]);
        let id = new_motion_id().unwrap();
        let mut eligible = net.state().eligible_now();
        eligible.extend(outsiders.iter().map(|o| short_key(o.peer_id())));
        net.act(
            &p[1],
            Event::Motion {
                net: net.id,
                id: id.clone(),
                kind: MotionKind::Impeach,
                target: p[0].peer_id(),
                eligible,
            },
        );
        assert_eq!(net.state().motions[0].eligible, 2);
    }

    #[test]
    fn only_the_leader_can_call_a_vote_to_remove_someone() {
        let p = people(3);
        let mut net = Net::founded_by(&p[0]);
        net.join(&p[1]);
        net.join(&p[2]);
        net.motion(&p[1], MotionKind::Kick, p[2].peer_id());
        assert!(net.state().motions.is_empty());
    }

    #[test]
    fn a_removed_member_is_ignored_and_cannot_rejoin() {
        let p = people(3);
        let mut net = Net::founded_by(&p[0]);
        net.join(&p[1]);
        net.join(&p[2]);
        let motion = net.motion(&p[0], MotionKind::Kick, p[2].peer_id());
        net.vote(&p[1], &motion, true);
        assert!(!net.state().is_member(p[2].peer_id()));

        net.join(&p[2]);
        let state = net.state();
        assert!(!state.is_member(p[2].peer_id()));
        assert!(state.banned.contains(&p[2].peer_id()));
    }

    #[test]
    fn a_majority_against_closes_the_motion() {
        let p = people(3);
        let mut net = Net::founded_by(&p[0]);
        net.join(&p[1]);
        net.join(&p[2]);
        let motion = net.motion(&p[1], MotionKind::Impeach, p[0].peer_id());
        net.vote(&p[0], &motion, false);
        net.vote(&p[2], &motion, false);
        let state = net.state();
        assert_eq!(state.motions[0].status, MotionStatus::Failed);
        assert_eq!(state.leader, Some(p[0].peer_id()));
    }

    #[test]
    fn a_vote_after_the_deadline_does_not_count() {
        let p = people(3);
        let mut net = Net::founded_by(&p[0]);
        net.join(&p[1]);
        net.join(&p[2]);
        let motion = net.motion(&p[1], MotionKind::Impeach, p[0].peer_id());
        net.clock += MOTION_LIFETIME_SECS + 60;
        net.vote(&p[2], &motion, true);
        let state = net.state();
        assert_eq!(state.motions[0].status, MotionStatus::Expired);
        assert_eq!(state.leader, Some(p[0].peer_id()));
    }

    #[test]
    fn a_changed_vote_replaces_the_old_one() {
        let p = people(5);
        let mut net = Net::founded_by(&p[0]);
        for who in &p[1..] {
            net.join(who);
        }
        let motion = net.motion(&p[1], MotionKind::Impeach, p[0].peer_id());
        net.vote(&p[2], &motion, true);
        net.vote(&p[2], &motion, false);
        let state = net.state();
        assert_eq!((state.motions[0].yes, state.motions[0].no), (1, 1));
    }

    #[test]
    fn only_the_leader_sets_policy_and_announces() {
        let p = people(2);
        let mut net = Net::founded_by(&p[0]);
        net.join(&p[1]);
        net.act(
            &p[1],
            Event::Policy {
                net: net.id,
                low_data_mandatory: true,
            },
        );
        net.act(
            &p[1],
            Event::Announce {
                net: net.id,
                text: "I am in charge".into(),
                ping: true,
            },
        );
        let state = net.state();
        assert!(!state.low_data_mandatory);
        assert!(state.announcements.is_empty());

        net.act(
            &p[0],
            Event::Policy {
                net: net.id,
                low_data_mandatory: true,
            },
        );
        net.act(
            &p[0],
            Event::Announce {
                net: net.id,
                text: "meeting at 6".into(),
                ping: true,
            },
        );
        let state = net.state();
        assert!(state.low_data_mandatory);
        assert_eq!(state.announcements.len(), 1);
    }

    #[test]
    fn a_leader_cannot_ping_everybody_more_than_once_in_ten_minutes() {
        let p = people(1);
        let mut net = Net::founded_by(&p[0]);
        for text in ["one", "two"] {
            net.act(
                &p[0],
                Event::Announce {
                    net: net.id,
                    text: text.into(),
                    ping: true,
                },
            );
        }
        net.clock += PING_INTERVAL_SECS;
        net.act(
            &p[0],
            Event::Announce {
                net: net.id,
                text: "three".into(),
                ping: true,
            },
        );
        let pings: Vec<bool> = net.state().announcements.iter().map(|a| a.ping).collect();
        assert_eq!(pings, vec![true, false, true]);
    }

    /// Otherwise a vote cast in one net could be lifted and replayed in
    /// another where the same people are members.
    #[test]
    fn an_event_naming_another_net_is_ignored() {
        let p = people(1);
        let mut net = Net::founded_by(&p[0]);
        let (elsewhere, _) = NetId::found(p[0].peer_id()).unwrap();
        net.act(
            &p[0],
            Event::Policy {
                net: elsewhere,
                low_data_mandatory: true,
            },
        );
        assert!(!net.state().low_data_mandatory);
    }

    #[test]
    fn a_net_has_distinct_governance_and_general_channels() {
        let p = people(1);
        let (id, _) = NetId::found(p[0].peer_id()).unwrap();
        assert_ne!(id.governance(), id.general());
        assert_ne!(id.general(), ChannelId::neighborhood());
        assert_ne!(id.governance(), ChannelId::directory());
    }
}
