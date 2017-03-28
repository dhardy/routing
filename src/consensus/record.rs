// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::PeerId;
use super::consensus_state::Cluster;
use maidsafe_utilities::serialisation;
use rust_sodium::crypto::{hash, sign};
use rust_sodium::crypto::hash::sha256::Digest;
use rustc_serialize::Encodable;
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::iter::Rev;
use std::vec::IntoIter;

pub trait Entry: Encodable + Clone + PartialEq + Eq + Hash {}

/// An enum representing possible configuration (membership) changes - these have to be handled
/// separately
#[derive(Clone, RustcEncodable, PartialEq, Eq, Hash)]
pub enum ConfigurationEntry<T: PeerId> {
    NodeAdded(T, sign::PublicKey),
    NodeRemoved(T, sign::PublicKey),
    ClusterMerge(Cluster<T>),
    ClusterSplit(Cluster<T>),
}

/// A record entry type - can be either of regular entry (of type defined by the application) or a
/// configuration change entry
#[derive(Clone, RustcEncodable, PartialEq, Eq, Hash)]
pub enum RecordEntry<T: PeerId, E: Entry> {
    Regular(E),
    Config(ConfigurationEntry<T>),
}

/// A "locked" record entry is an entry that has a validatable history - it can be validated by
/// checking the hashes of the previous entries
#[derive(Clone, RustcEncodable)]
pub struct LockedRecordEntry<T: PeerId, E: Entry> {
    pub entry: RecordEntry<T, E>,
    pub parent_hash: Digest,
}

impl<T: PeerId, E: Entry> LockedRecordEntry<T, E> {
    /// Calculate the hash of the entry
    pub fn hash(&self) -> Digest {
        let bytes = serialisation::serialise(self)
            .ok()
            .expect("Serialisation failed");
        hash::sha256::hash(&bytes)
    }

    /// Signs the entry with a given key.
    pub fn signature(&self, key: &sign::SecretKey) -> sign::Signature {
        let bytes = serialisation::serialise(self)
            .ok()
            .expect("Message content serialisation failure");
        sign::sign_detached(&bytes, key)
    }

    /// Verifies the entry signature.
    pub fn verify(&self, sig: &sign::Signature, key: &sign::PublicKey) -> bool {
        let bytes = serialisation::serialise(self)
            .ok()
            .expect("Message content serialisation failure");
        sign::verify_detached(sig, &bytes, key)
    }

    /// Create a new entry to be inserted after a given one
    pub fn new_after_entry(entry: RecordEntry<T, E>,
                           parent: &LockedRecordEntry<T, E>)
                           -> LockedRecordEntry<T, E> {
        LockedRecordEntry {
            entry: entry,
            parent_hash: parent.hash(),
        }
    }

    /// Create a new entry with a given hash of the previous entry
    pub fn new_after_hash(entry: RecordEntry<T, E>, parent: Digest) -> LockedRecordEntry<T, E> {
        LockedRecordEntry {
            entry: entry,
            parent_hash: parent,
        }
    }
}

/// Type representing a locked entry that is signed by the members of the cluster
#[derive(Clone, RustcEncodable)]
pub struct SignedRecordEntry<T: PeerId, E: Entry> {
    pub entry: LockedRecordEntry<T, E>,
    pub signatures: BTreeMap<T, sign::Signature>,
}

impl<T: PeerId, E: Entry> SignedRecordEntry<T, E> {
    /// Returns the number of signatures that are valid with respect to the given cluster members
    /// list.
    pub fn valid_sig_count(&self, cluster: &Cluster<T>) -> usize {
        self.signatures
            .iter()
            .filter(|&(name, sig)| {
                        cluster
                            .get(name)
                            .map_or(false, |key| self.entry.verify(sig, key))
                    })
            .count()
    }

    /// Signs the entry with a given key and returns the signature.
    pub fn sign(&mut self, peer_id: T, peer_key: &sign::SecretKey) -> sign::Signature {
        let sig = self.entry.signature(peer_key);
        self.signatures.insert(peer_id, sig);
        sig
    }

    /// Adds the signature by the given peer.
    pub fn add_signature(&mut self, peer_id: T, sig: sign::Signature) {
        self.signatures.insert(peer_id, sig);
    }
}

/// The record struct - it contains a list of signed record entries, as well as information
/// regarding the entries preceding the ones contained in it and which entries are considered
/// committed - accepted by a quorum of members, and therefore immutable in the future.
pub struct Record<T: PeerId, E: Entry> {
    start_hash: Digest,
    last_hash: Digest,
    record: HashMap<Digest, SignedRecordEntry<T, E>>,
    entry_indices: HashMap<Digest, usize>,
    last_committed: Digest,
}

impl<T: PeerId, E: Entry> Record<T, E> {
    /// Creates a new record starting at index 0.
    pub fn new() -> Record<T, E> {
        let mut initial_indices = HashMap::new();
        initial_indices.insert(Digest([0; 32]), 0);
        Record {
            start_hash: Digest([0; 32]),
            last_hash: Digest([0; 32]),
            record: HashMap::new(),
            entry_indices: initial_indices,
            last_committed: Digest([0; 32]),
        }
    }

    /// Creates a record starting at a given index, with a given starting hash.
    pub fn new_with_offset(start_hash: Digest) -> Record<T, E> {
        let mut initial_indices = HashMap::new();
        initial_indices.insert(start_hash, 0);
        Record {
            start_hash: start_hash,
            last_hash: start_hash,
            record: HashMap::new(),
            entry_indices: initial_indices,
            last_committed: start_hash,
        }
    }

    /// Returns a reference to the record entry at the given index (if we have it in our record).
    pub fn get(&self, hash: &Digest) -> Option<&SignedRecordEntry<T, E>> {
        self.record.get(hash)
    }

    /// Returns the index of an entry in the record that has the given hash. The indices can then
    /// be used to find out which entry is earlier in the record.
    pub fn get_index(&self, hash: &Digest) -> Option<usize> {
        self.entry_indices.get(hash).map(|x| *x)
    }

    /// Returns a  mutable reference to the record entry at the given index (if we have it in our
    /// record).
    pub fn get_mut(&mut self, hash: &Digest) -> Option<&mut SignedRecordEntry<T, E>> {
        self.record.get_mut(hash)
    }

    /// Checks whether an entry with a given `hash` exists.
    pub fn contains(&self, hash: &Digest) -> bool {
        self.record.contains_key(hash)
    }

    /// Returns the last index that we have in the record.
    pub fn last_hash(&self) -> Digest {
        self.last_hash
    }

    /// Returns the last committed index in the record.
    pub fn last_committed(&self) -> Digest {
        self.last_committed
    }

    /// Returns an iterator over the entries in range (start,end].
    pub fn range(&self, start: &Digest, end: &Digest) -> Rev<IntoIter<&SignedRecordEntry<T, E>>> {
        self.rev_range(start, end).rev()
    }

    /// Returns an iterator over the reversed range of entries: [end, start)
    pub fn rev_range(&self, start: &Digest, end: &Digest) -> IntoIter<&SignedRecordEntry<T, E>> {
        if (!self.record.contains_key(start) && self.start_hash != *start) ||
           !self.record.contains_key(end) {
            Vec::new().into_iter()
        } else {
            let mut cur_hash = *end;
            let mut result = Vec::new();
            while cur_hash != *start {
                let entry = self.record.get(&cur_hash).unwrap();
                result.push(entry);
                cur_hash = entry.entry.parent_hash;
            }
            result.into_iter()
        }
    }

    /// Returns the entries from the record beginning at the given index as a vec of references.
    pub fn entries_since(&self, start: &Digest) -> Vec<&SignedRecordEntry<T, E>> {
        self.range(start, &self.last_hash).collect()
    }

    /// Returns the starting hash of the record.
    pub fn start_hash(&self) -> Digest {
        self.start_hash
    }

    /// Appends the given entry to the end of the record.
    pub fn append_entry(&mut self, entry: RecordEntry<T, E>) -> Digest {
        let locked = LockedRecordEntry::new_after_hash(entry, self.last_hash());
        let hash = locked.hash();
        let signed = SignedRecordEntry {
            entry: locked,
            signatures: BTreeMap::new(),
        };
        let index = self.get_index(&signed.entry.parent_hash).unwrap() + 1;
        self.record.insert(hash, signed);
        self.entry_indices.insert(hash, index);
        self.last_hash = hash;
        hash
    }

    /// Rewinds the record back to a given point, removing the entries along the way
    pub fn rewind(&mut self, digest: &Digest) {
        while self.last_hash != *digest {
            if let Some(entry) = self.record.remove(digest) {
                let _ = self.entry_indices.remove(digest);
                self.last_hash = entry.entry.parent_hash;
            } else {
                return;
            }
        }
    }

    /// Updates the record with the given entries. The existing records only get signed with the
    /// new signatures, the new records get inserted. If the given entries and the current record
    /// diverge, the old entries since the divergence point get deleted.
    /// The function returns without doing anything if the chain of hashes of the new entries is
    /// invalid or if the update would result in removal of a committed entry.
    pub fn update_entries(&mut self, start: &Digest, entries: Vec<SignedRecordEntry<T, E>>) {
        // first, validate the chain of hashes
        let mut cur_hash = *start;
        for entry in entries.iter() {
            if entry.entry.parent_hash != cur_hash {
                return;
            }
            cur_hash = entry.entry.hash();
        }

        // split into entries that already exist and new ones
        let mut to_existing = true;
        let mut existing = Vec::new();
        let mut rest = Vec::new();
        for entry in entries {
            if to_existing && self.record.contains_key(&entry.entry.hash()) {
                existing.push(entry);
            } else {
                rest.push(entry);
                to_existing = false;
            }
        }

        // merge signatures
        for entry in existing {
            let hash = entry.entry.hash();
            for (name, sig) in entry.signatures {
                self.add_signature(&hash, name, sig);
            }
        }

        if !rest.is_empty() {
            // the parent hash of the first entry from the rest is the last one in common between
            // our current record and the given entries
            let divergence_point = rest[0].entry.parent_hash;

            // make sure that we won't remove committed entries
            if self.entry_indices[&divergence_point] < self.entry_indices[&self.last_committed] {
                return;
            }

            // remove the entries after the divergence point
            self.rewind(&divergence_point);

            // add the new entries
            for entry in rest {
                let hash = entry.entry.hash();
                let index = self.entry_indices[&entry.entry.parent_hash] + 1;
                self.record.insert(hash, entry);
                self.entry_indices.insert(hash, index);
                self.last_hash = hash;
            }
        }
    }

    /// Adds a signature to the entry at the given index.
    pub fn add_signature(&mut self,
                         hash: &Digest,
                         peer_id: T,
                         signature: sign::Signature)
                         -> usize {
        if let Some(entry) = self.get_mut(hash) {
            entry.add_signature(peer_id, signature);
            entry.signatures.len()
        } else {
            0
        }
    }

    /// Signs an entry at the given index with `peer_key` and returns the signature if successful
    pub fn sign(&mut self,
                hash: &Digest,
                peer_id: T,
                peer_key: &sign::SecretKey)
                -> Option<sign::Signature> {
        if let Some(entry) = self.get_mut(hash) {
            Some(entry.sign(peer_id, peer_key))
        } else {
            None
        }
    }

    /// Commits the entries up to the given index.
    pub fn commit(&mut self, hash: Digest) {
        self.last_committed = hash;
    }
}
