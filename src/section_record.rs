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

/// We use this to identify record entries.
//TODO: why are we using SHA256?
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, RustcEncodable, RustcDecodable, Hash)]
pub struct RecordId {
    digest: sha256::Digest,
}

impl fmt::Debug for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.digest.as_ref();
        write!(f, "{:02x}{:02x}{:02x}..", bytes[0], bytes[1], bytes[2])
    }
}

/// What happened in a change
#[derive(Clone, Debug, RustcEncodable, RustcDecodable, Eq, PartialEq, Hash)]
pub enum SectionChange {
    /// The node starting a network
    InitialNode(XorName),
    /// Used for records which don't go back to the `InitialNode`.
    ///
    /// Like `InitialNode`, this is not a successor to anything.
    StartPoint(RecordId),
    /// Indicates an agreement to split. This is the last entry before split.
    SectionSplit {
        prev_id: RecordId,
    },
    /// Record addition of a candidate node. Once accepted as a candidate, it must complete
    /// resource proofs to be accepted as a full node, otherwise it times out.
    AddCandidate {
        // TODO: some fields can probably be removed later, or may not need to be in the record
        prev_id: RecordId,
        new_pub_id: PublicId,
        /// Client authority of the candidate
        client_auth: Authority<XorName>,
    },
    /// Record the approval of a candidate to become a full routing node.
    /// 
    /// (The name may be a little confusing since the node was already added as a candidate. But
    /// my preference, `ApproveCandidate`, sounds too much like the old `CandidateApproval`.)
    AddNode {
        // TODO: some fields can probably be removed later, or may not need to be in the record
        prev_id: RecordId,
        new_pub_id: PublicId,
        /// Client authority of the candidate
        client_auth: Authority<XorName>,
        /// The `PublicId`s of all routing table contacts shared by the nodes in our section.
        sections: SectionMap,
    },
    /*
    NodeLost {
        prev_hash: RecordId,
        lost_name: XorName,
    },
    SectionMerge {
        /// Hash of previous block for lexicographically lesser section (P0).
        left_hash: RecordId,
        /// Hash of previous block for lexicographically greater section (P1).
        right_hash: RecordId,
    },
    */
}

impl SectionChange {
    // higher value is higher priority, equal only if types are equal
    fn priority(&self) -> u32 {
        use self::SectionChange::*;
        match *self {
            InitialNode(_) => 10000,
            StartPoint(_) => 9999,
            SectionSplit {..} => 2000,
            AddCandidate {..} => 100,
            AddNode {..} => 1000,
        }
    }
    
    /// Update the previous entry identifier, if applicable.
    pub fn update_prev(mut self, id: RecordId) -> Self {
        use self::SectionChange::*;
        match self {
            InitialNode(_) | StartPoint(_) => {}
            SectionSplit { ref mut prev_id } |
            AddCandidate { ref mut prev_id, .. } |
            AddNode { ref mut prev_id, .. } => {
                *prev_id = id
            }
        }
        self
    }
}

/// Entry recording a membership change
// TODO: maybe delete this entirely in favour of just using SectionChange, the id is computable
// from the change field (and doesn't need to be stored).
// TODO: should fields be pub?
#[derive(Clone, RustcEncodable, RustcDecodable, Eq, PartialEq, Hash)]
pub struct RecordEntry {
    // Identifier of this change, applied over the previous change
    pub id: RecordId,
    // List of members before applying this change, sorted by name.
    // TODO: do we want to only store diffs to member list instead?
    pub members: BTreeSet<PublicId>,
    // Change itself
    pub change: SectionChange,
}

impl Ord for RecordEntry {
    fn cmp(&self, other: &RecordEntry) -> Ordering {
        match (self.change.priority(), other.change.priority()) {
            // If same type, any consistent ordering is sufficient
            (x, y) if x == y => self.id.cmp(&other.id),
            (x, y) if x < y => Ordering::Less,
            _ => Ordering::Greater,
        }
    }
}

impl PartialOrd for RecordEntry {
    fn partial_cmp(&self, other: &RecordEntry) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}


impl RecordEntry {
    /// Create a new entry, given the members of the section before a change, and the change itself.
    ///
    /// The list of members is sorted in this method.
    pub fn new(members: BTreeSet<PublicId>, change: SectionChange) -> Self {
        let id = if let SectionChange::StartPoint(id) = change {
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
            RecordId { digest: sha256::hash(&buf) }
        };

        RecordEntry {
            id: id,
            members: members,
            change: change,
        }
    }

    // TODO: maybe return a Result<(), SomeError>
    /// Checks that (one of) our own "previous entry identifiers" is `prev_entry`.
    pub fn is_successor_of(&self, prev_entry: &RecordEntry) -> bool {
        use self::SectionChange::*;

        // Check hash.
        match self.change {
            InitialNode(..) | StartPoint(..) => {
                warn!("{:?} RecordEntry::is_successor_of called on initial entry", self);
                return false;
            }
            /*
            NodeLost { prev_hash, .. } |
            */
            SectionSplit { ref prev_id, .. } |
            AddCandidate { ref prev_id, .. } |
            AddNode { ref prev_id, .. } => {
                if *prev_id != prev_entry.id {
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

impl fmt::Debug for RecordEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RecordEntry {{ id: {:?}, members: {:?}, change: {:?}", &self.id, &self.members, &self.change)
    }
}


/// Record of section membership changes
#[derive(Clone)]
pub struct SectionRecord {
    own_id: PublicId,
    entries: Vec<RecordEntry>,
}

impl SectionRecord {
    /// Create a new record as the first node (i.e. state that this is the initial node in
    /// the network).
    pub fn new_first(our_id: PublicId) -> Self {
        let change = SectionChange::InitialNode(*our_id.name());
        let entry = RecordEntry::new(BTreeSet::new(), change);
        SectionRecord { entries: vec![entry], own_id: our_id }
    }

    /// Create a new, empty record.
    ///
    /// The record is invalid until an entry has been inserted.
    pub fn new_empty(our_id: PublicId) -> Self {
        SectionRecord { entries: vec![], own_id: our_id }
    }

    /// Node has relocated: reset the record and change our id.
    /// 
    /// The record is cleared and given a new "start point" where `record_id` is the starting point in
    /// our neighbour's record, and `members` is  the list of members in our section (after adding
    /// us).
    pub fn relocate(&mut self, our_id: PublicId, record_id: RecordId, members: BTreeSet<PublicId>) {
        if !self.entries.is_empty() {
            // Note: this currently happens routinely since new nodes are relocated _both_ when
            // joining as a candidate and when being approved. This shouldn't happen later.
            warn!("Node({:?}) Reset to {:?} from non-empty record: {:?}", self.own_id.name(), our_id.name(), self);
        }

        self.own_id = our_id;
        let change = SectionChange::StartPoint(record_id);
        let entry = RecordEntry::new(members, change);
        self.entries = vec![entry];
    }

    /// Try to append an entry to the record
    pub fn append(&mut self, entry: RecordEntry) -> Option<&RecordEntry> {
        if let Some(prev) = self.entries.last() {
            if !entry.is_successor_of(prev) {
                // This is an error in our collective-agreement algorithm:
                // TODO: if we have a problem here, we should try to re-sync the record
                error!("Node({:?}) Attempted to append an invalid successor to record (may not be recoverable); record: {:?}", self.own_id.name(), self);
                return None;
            }
        } else {
            // This is a fatal code error, and probably going to happen again if rebooted.
            panic!("Node({:?}) Attempted to append to record before initialisation.", self.own_id.name());
        }

        info!("Node({:?}) Appending record entry: {:?}", self.own_id.name(), entry);
        self.entries.push(entry);
        self.entries.last()
    }

    /// Get our public identifier
    pub fn own_id(&self) -> &PublicId {
        &self.own_id
    }
    
    /// Return the last identifier in the record, or none if the record is entry.
    // TODO: I don't think we'll want this eventually. At least, check usages.
    pub fn last_id(&self) -> Option<RecordId> {
        self.entries.last().map(|entry| entry.id)
    }
}

impl fmt::Debug for SectionRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Section record of {:?}:", self.own_id)?;
        if self.entries.len() <= 3 {
            write!(f, "\tRecord: {:?}", self.entries)
        } else {
            let ll = self.entries.len();
            write!(f,
                    "\tRecord: [{:?}, <omitted {} entries>, {:?}, {:?}]",
                   self.entries[0],
                   ll - 3,
                   self.entries[ll - 2],
                   self.entries[ll - 1])
        }
    }
}

#[derive(Debug)]
pub enum SectionRecordError {
    InvalidState,
    PrevIdMismatch,
}
