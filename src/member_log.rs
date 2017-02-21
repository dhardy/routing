// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

#![cfg_attr(rustfmt, rustfmt_skip)]

use id::PublicId;
use maidsafe_utilities::serialisation::serialise;
use rust_sodium::crypto::hash::sha256;
use std::fmt;
use std::collections::BTreeSet;
use xor_name::XorName;
use std::cmp::Ordering;
use routing_table::Authority;
use route_manager::SectionMap;

/// We use this to identify log entries.
//TODO: why are we using SHA256?
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, RustcEncodable, RustcDecodable, Hash)]
pub struct LogId {
    digest: sha256::Digest,
}

impl fmt::Debug for LogId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.digest.as_ref();
        write!(f, "{:02x}{:02x}{:02x}..", bytes[0], bytes[1], bytes[2])
    }
}

/// What happened in a change
#[derive(Clone, Debug, RustcEncodable, RustcDecodable, Eq, PartialEq, Hash)]
pub enum MemberChange {
    /// The node starting a network
    InitialNode(XorName),
    /// Used for logs which don't go back to the `InitialNode`.
    ///
    /// Like `InitialNode`, this is not a successor to anything.
    StartPoint(LogId),
    /// Indicates an agreement to split. This is the last entry before split.
    SectionSplit {
        prev_id: LogId,
    },
    /// Record the approval of a candidate to become a full routing node.
    AddNode {
        prev_id: LogId,
        new_id: PublicId,
        // TODO: we don't really want these details in the log. Just adding now to simplify
        // converting existing code.
        /// Client authority of the candidate
        client_auth: Authority<XorName>,
        /// The `PublicId`s of all routing table contacts shared by the nodes in our section.
        sections: SectionMap,
    },
    /*
    NodeLost {
        prev_hash: LogId,
        lost_name: XorName,
    },
    SectionMerge {
        /// Hash of previous block for lexicographically lesser section (P0).
        left_hash: LogId,
        /// Hash of previous block for lexicographically greater section (P1).
        right_hash: LogId,
    },
    */
}

impl MemberChange {
    // higher value is higher priority, equal only if types are equal
    fn priority(&self) -> u32 {
        use self::MemberChange::*;
        match *self {
            InitialNode(_) => 10000,
            StartPoint(_) => 9999,
            SectionSplit {..} => 2000,
            AddNode {..} => 1000,
        }
    }
    
    /// Update the previous entry identifier, if applicable.
    pub fn update_prev(mut self, id: LogId) -> Self {
        use self::MemberChange::*;
        match self {
            InitialNode(_) | StartPoint(_) => {}
            SectionSplit { ref mut prev_id } |
            AddNode { ref mut prev_id, .. } => {
                *prev_id = id
            }
        }
        self
    }
}

/// Entry recording a membership change
// TODO: maybe delete this entirely in favour of just using MemberChange, the id is computable
// from the change field (and doesn't need to be stored).
// TODO: should fields be pub?
#[derive(Clone, RustcEncodable, RustcDecodable, Eq, PartialEq, Hash)]
pub struct MemberEntry {
    // Identifier of this change, applied over the previous change
    pub id: LogId,
    // List of members before applying this change, sorted by name.
    // TODO: do we want to only store diffs to member list instead?
    pub members: BTreeSet<PublicId>,
    // Change itself
    pub change: MemberChange,
}

impl Ord for MemberEntry {
    fn cmp(&self, other: &MemberEntry) -> Ordering {
        match (self.change.priority(), other.change.priority()) {
            // If same type, any consistent ordering is sufficient
            (x, y) if x == y => self.id.cmp(&other.id),
            (x, y) if x < y => Ordering::Less,
            _ => Ordering::Greater,
        }
    }
}

impl PartialOrd for MemberEntry {
    fn partial_cmp(&self, other: &MemberEntry) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}


impl MemberEntry {
    /// Create a new entry, given the members of the section before a change, and the change itself.
    ///
    /// The list of members is sorted in this method.
    pub fn new(members: BTreeSet<PublicId>, change: MemberChange) -> Self {
        let id = if let MemberChange::StartPoint(id) = change {
            //TODO: this is a hack; maybe there's a better solution?
            id
        } else {
            // Append all entries into a buffer and create a hash of that.
            // TODO: for security, the hash may want to include more details (e.g. full routing table)?
            let mut buf = vec![];
            // TODO: serialisation _shouldn't_ fail, but the API doesn't guarantee that it won't.
            // Find a way of handling this; ideally don't return a `Result` everywhere.
            buf.extend_from_slice(&unwrap!(serialise(&members)));
            buf.extend_from_slice(&unwrap!(serialise(&change)));
            LogId { digest: sha256::hash(&buf) }
        };

        MemberEntry {
            id: id,
            members: members,
            change: change,
        }
    }

    // TODO: maybe return a Result<(), SomeError>
    /// Checks that (one of) our own "previous entry identifiers" is `prev_entry`.
    pub fn is_successor_of(&self, prev_entry: &MemberEntry) -> bool {
        use self::MemberChange::*;

        // Check hash.
        match self.change {
            InitialNode(..) | StartPoint(..) => {
                warn!("{:?} MemberEntry::is_successor_of called on initial entry", self);
                return false;
            }
            /*
            NodeLost { prev_hash, .. } |
            */
            SectionSplit { prev_id, .. } | AddNode { prev_id, .. } => {
                if prev_id != prev_entry.id {
                    return false;
                }
            },
            /*
            SectionMerge { left_hash, right_hash, .. } => {
                let prev_hash = prev_entry.id;
                if left_hash != prev_hash && right_hash != prev_hash {
                    return false;
                }
            }
            */
        }

        // TODO: check signatures
        true
    }
}

impl fmt::Debug for MemberEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MemberEntry {{ id: {:?}, members: {:?}, change: {:?}", &self.id, &self.members, &self.change)
    }
}


/// Log of section membership changes
#[derive(Clone)]
pub struct MemberLog {
    own_id: PublicId,
    log: Vec<MemberEntry>,
}

impl MemberLog {
    /// Create a new log as the first node (i.e. state in the log that this is the initial node in
    /// the network).
    pub fn new_first(our_id: PublicId) -> Self {
        let change = MemberChange::InitialNode(*our_id.name());
        let entry = MemberEntry::new(BTreeSet::new(), change);
        MemberLog { log: vec![entry], own_id: our_id }
    }

    /// Create a new, empty log.
    ///
    /// The log is invalid until an entry has been inserted.
    pub fn new_empty(our_id: PublicId) -> Self {
        MemberLog { log: vec![], own_id: our_id }
    }

    /// Node has relocated: reset the log and change our id.
    /// 
    /// The log is cleared and given a new "start point" where `log_id` is the starting point in
    /// our neighbour's log, and `members` is  the list of members in our section (after adding
    /// us).
    pub fn relocate(&mut self, our_id: PublicId, log_id: LogId, members: BTreeSet<PublicId>) {
        if !self.log.is_empty() {
            // Note: this currently happens routinely since new nodes are relocated _both_ when
            // joining as a candidate and when being approved. This shouldn't happen later.
            warn!("Node({:?}) Reset to {:?} from non-empty log: {:?}", self.own_id.name(), our_id.name(), self);
        }

        self.own_id = our_id;
        let change = MemberChange::StartPoint(log_id);
        let entry = MemberEntry::new(members, change);
        self.log = vec![entry];
    }

    /// Try to append an entry to the log
    pub fn append(&mut self, entry: MemberEntry) -> Option<&MemberEntry> {
        if let Some(prev) = self.log.last() {
            if !entry.is_successor_of(prev) {
                // This is an error in our collective-agreement algorithm:
                // TODO: if we have a problem here, we should try to re-sync the log
                error!("Node({:?}) Attempted to append an invalid successor to log (may not be recoverable); log: {:?}", self.own_id.name(), self);
                return None;
            }
        } else {
            // This is a fatal code error, and probably going to happen again if rebooted.
            panic!("Node({:?}) Attempted to append to log before initialisation.", self.own_id.name());
        }

        info!("Node({:?}) Appending log entry: {:?}", self.own_id.name(), entry);
        self.log.push(entry);
        self.log.last()
    }

    /// Get our public identifier
    pub fn own_id(&self) -> &PublicId {
        &self.own_id
    }
    
    /// Return the last identifier in the log, or none if the log is entry.
    // TODO: I don't think we'll want this eventually. At least, check usages.
    pub fn last_id(&self) -> Option<LogId> {
        self.log.last().map(|entry| entry.id)
    }
}

impl fmt::Debug for MemberLog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Member log of {:?}:", self.own_id)?;
        if self.log.len() <= 3 {
            write!(f, "\tLog: {:?}", self.log)
        } else {
            let ll = self.log.len();
            write!(f,
                    "\tLog: [{:?}, <omitted {} entries>, {:?}, {:?}]",
                   self.log[0],
                   ll - 3,
                   self.log[ll - 2],
                   self.log[ll - 1])
        }
    }
}

#[derive(Debug)]
pub enum MemberLogError {
    InvalidState,
    PrevIdMismatch,
}
