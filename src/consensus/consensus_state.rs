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

use super::TimerToken;
use super::error::Error;
use super::interface::{NetworkInterface, Scheduler};
use super::message::{AppendEntries, AppendEntriesResponse, Content, Message, RequestVote,
                     VoteResponse, VoteResponseEnum};
use super::record::{ConfigurationEntry, Entry, Record, RecordEntry, SignedRecordEntry};
use super::state::{State, Votes};
use crust::PeerId;
use rand;
use rand::distributions::{IndependentSample, Range};
use rust_sodium::crypto::hash::sha256::Digest;
use rust_sodium::crypto::sign;
use std::collections::{BTreeMap, HashSet};
use std::mem;

const MIN_HEARTBEAT_RANGE: u64 = 30;
const MAX_HEARTBEAT_RANGE: u64 = 45;
const HEARTBEAT_PERIOD: u64 = 20;
const VOTE_HIGH_WATERMARK: u64 = 10;

pub type Cluster = BTreeMap<PeerId, sign::PublicKey>;
pub type Result<T> = ::std::result::Result<T, Error>;
pub type ConsensusResult<E> = Result<Vec<RecordEntry<E>>>;

/// The structure containing all information relevant to the handling of the consensus.
pub struct ConsensusState<E: Entry> {
    our_id: PeerId,
    our_key: sign::SecretKey,
    current_term: u64,
    // record who to vote for and term in case of an election timeout
    lazy_vote: Option<(u64, PeerId)>,
    voted_for: Option<PeerId>,
    record: Record<E>,
    pending_entries: HashSet<RecordEntry<E>>,
    unsigned_entries: HashSet<Digest>,
    last_applied: Digest,
    state: State,
    cluster: Cluster,
}

impl<E: Entry> ConsensusState<E> {
    /// Method creating a new struct containing the state of the consensus algorithm in our node.
    /// `our_id` is the peer ID of this node, `our_key` is it's secret signing key. The `cluster`
    /// parameter should contain all the names currently in our cluster, along with their public
    /// keys for verification of the signatures. The `sched` parameter is necessary to schedule an
    /// initial heartbeat timeout.
    pub fn new<S: Scheduler>(our_id: PeerId,
                             our_key: sign::SecretKey,
                             cluster: Cluster,
                             sched: &mut S)
                             -> ConsensusState<E> {
        ConsensusState {
            our_id: our_id,
            our_key: our_key,
            current_term: 0,
            lazy_vote: None,
            voted_for: None,
            record: Record::new(),
            pending_entries: HashSet::new(),
            unsigned_entries: HashSet::new(),
            last_applied: Digest([0; 32]),
            state: State::Follower {
                election_token: Self::restart_election_timer(sched),
                current_leader: None,
            },
            cluster: cluster,
        }
    }

    /// Message handling method - all messages regarding consensus received by the client of the
    /// crate should be passed here along with an object that will allow for sending responses (in
    /// the `net` parameter).
    /// Returns a Vec of new record entries to be applied to the state machine.
    pub fn handle_message<I: NetworkInterface<E>, S: Scheduler>(&mut self,
                                                                message: Message<E>,
                                                                net: &mut I,
                                                                sched: &mut S)
                                                                -> ConsensusResult<E> {
        let Message {
            src,
            dst,
            content,
            signature,
        } = message;
        // separate scope to stop borrowing self via src_pub_key before content matching
        {
            let src_pub_key = match self.cluster.get(&src) {
                Some(key) => key,
                None => {
                    error!("Node({:?}): Unknown message source: {:?}", self.our_id, src);
                    return Err(Error::UnknownSource);
                }
            };
            // verify message signature
            if !content.verify(&signature, src_pub_key) {
                error!("Node({:?}): Message signature verification failure: src={:?}, dst={:?}",
                       self.our_id,
                       src,
                       dst);
                return Err(Error::InvalidSignature);
            }
        }
        // dispatch to the proper handler
        match content {
            Content::RequestVote(req) => self.handle_request_vote(net, req),
            Content::VoteResponse {
                response,
                response_sig,
            } => self.handle_vote_response(net, sched, src, response, response_sig),
            Content::AppendEntries(ae) => self.handle_append_entries(net, sched, src, ae),
            Content::AppendEntriesResponse(aer) => {
                self.handle_append_entries_response(net, src, aer)
            }
            _ => {
                trace!("Node({:?}): Got a message!", self.our_id);
                Ok(Vec::new())
            }
        }
    }

    /// Timeout handling method - the timers are identified by unique tokens. The timeout event
    /// themselves will be received by the client of the crate and should be passed to this method.
    /// `net` and `sched` parameters allow for sending responses and scheduling further timeout
    /// events, respectively.
    pub fn handle_timeout<I: NetworkInterface<E>, S: Scheduler>(&mut self,
                                                                token: TimerToken,
                                                                net: &mut I,
                                                                sched: &mut S) {
        match token {
            t if Some(t) == self.state.election_token() => {
                info!("Node({:?}): Timed out on election.", self.our_id);
                self.handle_election_timeout(net, sched);
            }
            t if Some(t) == self.state.heartbeat_token() => {
                info!("Node({:?}): Heartbeat timer expired - sending heartbeats.",
                      self.our_id);
                self.handle_heartbeat_timeout(net, sched);
            }
            t => {
                warn!("Node({:?}): Unknown timeout token {}!", self.our_id, t);
            }
        };
    }

    /// Called from outside to notify the consensus subsystem of an event that should be stored in
    /// the record.
    /// If we are the leader, appends the entry to the record and broadcasts `AppendEntries`.
    /// Otherwise, adds it to `pending_entries` and signs and optionally commits any corresponding
    /// entries.
    pub fn propose_entry<I: NetworkInterface<E>>(&mut self,
                                                 net: &mut I,
                                                 entry: RecordEntry<E>)
                                                 -> ConsensusResult<E> {
        if self.state.is_leader() {
            let hash = self.record.append_entry(entry);
            self.record.sign(&hash, self.our_id, &self.our_key);
            for peer in self.cluster.keys().filter(|&name| *name != self.our_id) {
                self.send_append_entries(net, *peer, false);
            }
            Ok(Vec::new())
        } else {
            self.pending_entries.insert(entry);
            self.sign_correct_entries(net);
            self.commit_fully_signed()
        }
    }

    /// Modifies `cluster` according to the given entry.
    fn apply_entry(cluster: &mut Cluster, entry: &ConfigurationEntry) {
        match *entry {
            ConfigurationEntry::NodeAdded(name, key) => {
                cluster.insert(name, key);
            }
            ConfigurationEntry::NodeRemoved(name, _) => {
                cluster.remove(&name);
            }
            ConfigurationEntry::ClusterMerge(ref new_nodes) => {
                let mut to_add = new_nodes.clone();
                cluster.append(&mut to_add);
            }
            ConfigurationEntry::ClusterSplit(ref dropped_nodes) => {
                for name in dropped_nodes.keys() {
                    cluster.remove(name);
                }
            }
        }
    }

    /// Reverses the modification of `cluster` according to the given entry.
    fn unapply_entry(cluster: &mut Cluster, entry: &ConfigurationEntry) {
        match *entry {
            ConfigurationEntry::NodeAdded(name, _) => {
                cluster.remove(&name);
            }
            ConfigurationEntry::NodeRemoved(name, key) => {
                cluster.insert(name, key);
            }
            ConfigurationEntry::ClusterMerge(ref new_nodes) => {
                for name in new_nodes.keys() {
                    cluster.remove(name);
                }
            }
            ConfigurationEntry::ClusterSplit(ref dropped_nodes) => {
                let mut to_add = dropped_nodes.clone();
                cluster.append(&mut to_add);
            }
        }
    }

    /// Returns the cluster members list as it was at the record entry identified by `hash`.
    fn cluster_at_hash(&self, hash: Digest) -> Cluster {
        let mut cluster = self.cluster.clone();
        let index = if let Some(index) = self.record.get_index(&hash) {
            index
        } else {
            error!("Node({:?}): unknown hash in cluster_at_hash", self.our_id);
            return BTreeMap::new();
        };
        let last_applied_index = self.record.get_index(&self.last_applied).unwrap();
        if index > last_applied_index {
            for signed_entry in self.record.range(&self.last_applied, &hash) {
                if let RecordEntry::Config(ref entry) = signed_entry.entry.entry {
                    Self::apply_entry(&mut cluster, entry);
                }
            }
        } else {
            for signed_entry in self.record.rev_range(&hash, &self.last_applied) {
                if let RecordEntry::Config(ref entry) = signed_entry.entry.entry {
                    Self::unapply_entry(&mut cluster, entry);
                }
            }
        }
        cluster
    }

    /// Returns whether `num` constitutes a quorum among `count` nodes.
    fn check_quorum(num: usize, count: usize) -> bool {
        100 * num >= 67 * count
    }

    /// Checks whether `num` constitutes a quorum in the current configuration.
    fn is_quorum(&self, num: usize) -> bool {
        Self::check_quorum(num, self.cluster.len())
    }

    /// Validates whether given entries could be cleanly and correctly appended after the entry
    /// identified by `start_hash`.
    fn validate_entries(&self, start_hash: Digest, entries: &[SignedRecordEntry<E>]) -> bool {
        let mut current_hash = start_hash;
        for signed_entry in entries.iter() {
            // check whether the parent hash is correct
            if signed_entry.entry.parent_hash != current_hash {
                return false;
            }
            current_hash = signed_entry.entry.hash();
        }
        true
    }

    /// Validates whether the entries presented form a valid chain and have a quorum of signatures
    /// each
    fn validate_committed(&self, start_hash: Digest, entries: &[SignedRecordEntry<E>]) -> bool {
        let mut current_hash = start_hash;
        let mut cluster = self.cluster_at_hash(current_hash);
        for signed_entry in entries.iter() {
            // check whether the parent hash is correct
            if signed_entry.entry.parent_hash != current_hash {
                return false;
            }
            // check whether it is signed by a quorum
            let valid_sig_count = signed_entry.valid_sig_count(&cluster);
            if !Self::check_quorum(valid_sig_count, cluster.len()) {
                return false;
            }
            // modify the cluster accordingly if necessary
            if let RecordEntry::Config(ref entry) = signed_entry.entry.entry {
                Self::apply_entry(&mut cluster, entry);
            }
            current_hash = signed_entry.entry.hash();
        }
        true
    }

    /// Verifies whether the candidate requesting our vote has all committed entries that we have.
    /// Requests additional information when it can't be verified.
    fn verify_log_prefix<I: NetworkInterface<E>>(&self, net: &mut I, req: &RequestVote<E>) -> bool {
        let last_committed_index = self.record
            .get_index(&self.record.last_committed())
            .unwrap();
        let candidate_last_committed = self.record.get_index(&req.last_committed_hash);
        match candidate_last_committed {
            Some(cand_last_index) if cand_last_index < last_committed_index => {
                warn!("Node({:?}): Received RequestVote from a candidate {:?} with a shorter \
                       record; denying",
                      self.our_id,
                      req.candidate_name);
                self.send_vote_response(net, VoteResponseEnum::Denied, req.candidate_name);
                false
            }
            Some(cand_last_index) if cand_last_index == last_committed_index => true,
            _ if !req.committed_entries.is_empty() => {
                if !self.validate_committed(self.record.last_committed(), &req.committed_entries) {
                    warn!("Node({:?}): Validation of the record entries in RequestVote from \
                           candidate {:?} failed; denying",
                          self.our_id,
                          req.candidate_name);
                    self.send_vote_response(net, VoteResponseEnum::Denied, req.candidate_name);
                    false
                } else {
                    // TODO: we can append and commit the presented entries since they are
                    // apparently signed by a quorum
                    true
                }
            }
            _ => {
                info!("Node({:?}): Received RequestVote from candidate {:?}, but cannot verify \
                       record prefix - requesting proof",
                      self.our_id,
                      req.candidate_name);
                self.send_vote_response(net,
                                        VoteResponseEnum::RequestProof {
                                            last_committed: self.record.last_committed(),
                                        },
                                        req.candidate_name);
                false
            }
        }
    }

    /// This method handles the vote requests. If the request is valid, it either sends the vote
    /// immediately, or saves is as a "lazy vote" to be sent on timeout. Invalid requests are
    /// denied.
    fn handle_request_vote<I: NetworkInterface<E>>(&mut self,
                                                   net: &mut I,
                                                   req: RequestVote<E>)
                                                   -> ConsensusResult<E> {
        match self.voted_for {
            _ if req.term < self.current_term => {
                warn!("Node({:?}): Received a vote request for an old term: {} < {}",
                      self.our_id,
                      req.term,
                      self.current_term);
                self.send_vote_response(net, VoteResponseEnum::Denied, req.candidate_name);
            }
            Some(candidate) if candidate == req.candidate_name && req.term == self.current_term => {
                // we already voted for this candidate in this term; repeat the response
                self.send_vote_response(net, VoteResponseEnum::Granted, req.candidate_name);
            }
            Some(candidate) if req.term == self.current_term => {
                warn!("Node({:?}): Received RequestVote for term {} from {:?}, but already \
                          voted for {:?}",
                      self.our_id,
                      req.term,
                      req.candidate_name,
                      candidate);
                self.send_vote_response(net, VoteResponseEnum::Denied, req.candidate_name);
            }
            _ => {
                if self.verify_log_prefix(net, &req) {
                    match self.lazy_vote {
                        Some((t, _)) if t >= req.term => {
                            warn!("Node({:?}): Received RequestVote for term {}, but already \
                                      lazily voted in term {}",
                                  self.our_id,
                                  req.term,
                                  t);
                        }
                        _ if req.term < self.current_term + VOTE_HIGH_WATERMARK => {
                            // update lazy vote
                            self.lazy_vote = Some((req.term, req.candidate_name));
                        }
                        _ => {
                            warn!("Node({:?}): Received RequestVote for a term exceeding the \
                                      high watermark; denying",
                                  self.our_id);
                            self.send_vote_response(net,
                                                    VoteResponseEnum::Denied,
                                                    req.candidate_name);
                        }
                    }
                }
            }
        }
        Ok(Vec::new())
    }

    /// Handles the vote response - checks whether a vote was granted, saves it if yes and
    /// transitions us to the leader state if we collected a quorum of votes.
    fn handle_vote_response<I: NetworkInterface<E>, S: Scheduler>(&mut self,
                                                                  net: &mut I,
                                                                  sched: &mut S,
                                                                  src: PeerId,
                                                                  response: VoteResponse,
                                                                  sig: sign::Signature)
                                                                  -> ConsensusResult<E> {
        if (self.state.is_candidate() || self.state.is_leader()) &&
           response.term == self.current_term && response.candidate == self.our_id {
            match response.vote_granted {
                VoteResponseEnum::Granted => {
                    self.state
                        .votes_mut()
                        .unwrap()
                        .insert(src, (response, sig));
                    self.check_election(net, sched);
                }
                VoteResponseEnum::Denied => {
                    let _ = self.state.votes_mut().unwrap().remove(&src);
                }
                VoteResponseEnum::RequestProof { last_committed } => {
                    let entries = self.record.entries_since(&last_committed);
                    self.send_request_vote(net, src, entries.into_iter().cloned().collect());
                }
            }
        }
        Ok(Vec::new())
    }

    /// Checks whether we collected a quorum of votes and makes us the leader if yes.
    fn check_election<I: NetworkInterface<E>, S: Scheduler>(&mut self,
                                                            net: &mut I,
                                                            sched: &mut S) {
        let votes_count = if let Some(votes) = self.state.votes() {
            votes.len()
        } else {
            return;
        };
        if self.is_quorum(votes_count) {
            self.become_leader(net, sched);
        }
    }

    /// Checks whether the sender of an AppendEntries message presented us with a quorum of votes.
    fn check_for_new_leader<S: Scheduler>(&mut self,
                                          sched: &mut S,
                                          term: u64,
                                          leader: PeerId,
                                          votes: &Votes) {
        if (self.current_term == term && Some(leader) == self.state.current_leader()) ||
           term < self.current_term || votes.is_empty() {
            return;
        }
        if self.validate_votes(term, leader, votes) {
            self.current_term = term;
            self.become_follower(sched, leader);
        }
    }

    /// Returns whether a set of votes contains a quorum of valid votes for `leader`.
    fn validate_votes(&self, term: u64, leader: PeerId, votes: &Votes) -> bool {
        let valid_votes_count = votes
            .iter()
            .filter(|&(name, &(vote, sig))| {
                        vote.term == term && vote.candidate == leader &&
                        vote.vote_granted == VoteResponseEnum::Granted &&
                        self.cluster
                            .get(&name)
                            .map_or(false, |key| vote.verify_sig(sig, key))
                    })
            .count();
        self.is_quorum(valid_votes_count)
    }

    /// Checks whether the prev_log_* data from AppendEntries match our record.
    fn append_entries_matches(&self, ae: &AppendEntries<E>) -> bool {
        self.record.get(&ae.prev_log_hash).is_some() || ae.prev_log_hash == self.record.start_hash()
    }

    /// Updates `unsigned_entries` - collects the ones from `new_entries` that we have not yet
    /// signed and drops the ones that we no longer have in our record.
    fn update_unsigned(&mut self, new_entries: &[Digest]) {
        let to_drop: Vec<_> = self.unsigned_entries
            .iter()
            .filter(|digest| !self.record.contains(digest))
            .cloned()
            .collect();
        for hash in to_drop {
            self.unsigned_entries.remove(&hash);
        }
        let new_unsigned: Vec<_> = new_entries
            .into_iter()
            .filter(|hash| {
                        self.record
                            .get(hash)
                            .map_or(false, |entry| !entry.signatures.contains_key(&self.our_id))
                    })
            .cloned()
            .collect();
        for hash in new_unsigned {
            self.unsigned_entries.insert(hash);
        }
    }

    /// Signs the entries from `unsigned_entries` which have corresponding `pending_entries` and
    /// broadcasts AppendEntriesResponses for them.
    fn sign_correct_entries<I: NetworkInterface<E>>(&mut self, net: &mut I) {
        // collect all unsigned entries along with their indices in the record
        let mut hashes_to_sign: Vec<_> = self.unsigned_entries
            .iter()
            .filter_map(|digest| {
                            self.record
                                .get_index(digest)
                                .and_then(|index| Some((index, *digest)))
                        })
            .collect();
        // sort the entries by index
        hashes_to_sign.sort_by_key(|x| x.0);
        let last_committed_index = self.record
            .get_index(&self.record.last_committed())
            .unwrap();
        let mut signed = HashSet::new();
        // make a copy of pending entries to control which entries we have signed - we will be
        // removing signed entries so that we don't sign the same entry twice
        // we can't use `self.pending_entries` because we don't remove entries from there until
        // they are committed
        let mut pending_entries = self.pending_entries.clone();
        for (index, hash) in hashes_to_sign {
            // check whether we have the entry in pending entries
            let entry = self.record
                .get(&hash)
                .and_then(|entry| Some(entry.entry.entry.clone()));
            if !entry
                    .as_ref()
                    .map_or(false, |entry| pending_entries.contains(entry)) {
                continue;
            }
            // we have it - remove from the pending entries copy and sign
            pending_entries.remove(&entry.unwrap());
            // only signed the entry if we agree to its parent as well; consider committed entries
            // to be agreed on
            if index > last_committed_index + 1 &&
               !self.record
                    .get(&hash)
                    .map_or(false, |entry| signed.contains(&entry.entry.parent_hash)) {
                break;
            }
            // sign the entry
            let sig = self.record
                .sign(&hash, self.our_id, &self.our_key)
                .unwrap();
            self.unsigned_entries.remove(&hash);
            signed.insert(hash);
            // broadcast AppendEntriesResponse
            for peer in self.cluster.keys().filter(|&name| *name != self.our_id) {
                let request = Content::AppendEntriesResponse(AppendEntriesResponse::Success {
                                                                 hash: hash,
                                                                 signature: Some(sig),
                                                             });
                self.send_message(net, *peer, request);
            }
        }
    }

    /// Looks for a configuration entry without a quorum of votes. If it doesn't find one, returns
    /// `entries.len()`.
    fn find_first_config_without_quorum(&self, entries: &[&SignedRecordEntry<E>]) -> usize {
        let mut cluster = if entries.len() > 0 {
            self.cluster_at_hash(entries[0].entry.parent_hash)
        } else {
            return 0;
        };
        for i in 0..entries.len() {
            let entry = &entries[i];
            if let RecordEntry::Config(ref config_entry) = entry.entry.entry {
                let sigs_count = entry.valid_sig_count(&cluster);
                if !Self::check_quorum(sigs_count, cluster.len()) {
                    return i;
                }
                Self::apply_entry(&mut cluster, config_entry);
            }
        }
        entries.len()
    }

    /// Commits entries that gathered a quorum of signatures, applies committed cluster changes and
    /// returns a `Vec` of entries that are now safe to be applied to the state machine.
    fn commit_fully_signed(&mut self) -> ConsensusResult<E> {
        let (commit_hash, result) = {
            let to_check = self.record.entries_since(&self.record.last_committed());
            let first_no_quorum = self.find_first_config_without_quorum(&to_check);
            // apply all config entries with quorum
            for (index, entry) in to_check[0..first_no_quorum]
                    .into_iter()
                    .enumerate()
                    .filter_map(|(index, &entry)| if let RecordEntry::Config(ref c) =
                entry.entry.entry {
                                    Some((index, c))
                                } else {
                                    None
                                }) {
                Self::apply_entry(&mut self.cluster, entry);
                self.last_applied = to_check[index].entry.hash();
            }
            // find the latest entry with quorum that's earlier than first_no_quorum
            let mut current_index = if first_no_quorum > 0 {
                first_no_quorum - 1
            } else {
                return Ok(Vec::new());
            };
            // we have to follow which members were in the cluster at each point
            let mut cluster = self.cluster_at_hash(to_check[current_index].entry.parent_hash);
            loop {
                let num_sigs = to_check[current_index].valid_sig_count(&cluster);
                if Self::check_quorum(num_sigs, cluster.len()) {
                    break;
                }
                if current_index == 0 {
                    return Ok(Vec::new());
                }
                current_index -= 1;
                if let RecordEntry::Config(ref c) = to_check[current_index].entry.entry {
                    Self::unapply_entry(&mut cluster, c);
                }
            }
            // to_check borrows self immutably - we return those from an inner scope to satisfy the
            // borrow checker in self.record.commit()
            (to_check[current_index].entry.hash(),
             to_check[0..current_index + 1]
                 .into_iter()
                 .map(|entry| entry.entry.entry.clone())
                 .collect::<Vec<_>>())
        };
        self.record.commit(commit_hash);
        // remove corresponding pending entries
        for entry in result.iter() {
            self.pending_entries.remove(entry);
        }
        Ok(result)
    }

    /// Handles the `AppendEntries` message - possibly registers a new leader, switches to the
    /// `Follower` state and appends entries being sent to the record.
    fn handle_append_entries<I: NetworkInterface<E>, S: Scheduler>(&mut self,
                                                                   net: &mut I,
                                                                   sched: &mut S,
                                                                   src: PeerId,
                                                                   ae: AppendEntries<E>)
                                                                   -> ConsensusResult<E> {
        self.check_for_new_leader(sched, ae.term, src, &ae.votes);
        match self.state.current_leader() {
            Some(leader) if leader == src && ae.term == self.current_term => {
                *self.state.election_token_mut().unwrap() = Self::restart_election_timer(sched);
                self.lazy_vote = None;
                if self.append_entries_matches(&ae) &&
                   self.validate_entries(ae.prev_log_hash, &ae.entries) {
                    let AppendEntries {
                        entries,
                        prev_log_hash,
                        ..
                    } = ae;
                    // collect hashes of entries being appended for further reference
                    let hashes: Vec<_> = entries.iter().map(|entry| entry.entry.hash()).collect();
                    // add the new entries to the log
                    self.record.update_entries(&prev_log_hash, entries);
                    self.send_append_entries_response(net,
                                                      src,
                                                      AppendEntriesResponse::Success {
                                                          hash: self.record.last_hash(),
                                                          signature: None,
                                                      });
                    // update the unsigned entries cache
                    self.update_unsigned(&hashes);
                    // sign whichever entries should be now signed
                    self.sign_correct_entries(net);
                    // commit fully signed
                    return self.commit_fully_signed();
                } else {
                    self.send_append_entries_response(net, src, AppendEntriesResponse::Failure);
                }
            }
            _ if ae.term >= self.current_term => {
                self.send_append_entries_response(net, src, AppendEntriesResponse::VotesRequired);
            }
            _ => (),
        }
        Ok(Vec::new())
    }

    /// Handles the AppendEntriesResponse message - updates the followers data and resends the
    /// entries with votes appended, if needed.
    fn handle_append_entries_response<I: NetworkInterface<E>>(&mut self,
                                                              net: &mut I,
                                                              src: PeerId,
                                                              aer: AppendEntriesResponse)
                                                              -> ConsensusResult<E> {
        match aer {
            AppendEntriesResponse::Success { hash, signature } => {
                if self.record.contains(&hash) {
                    if let Some(signature) = signature {
                        if self.cluster
                               .get(&src)
                               .map_or(false, |pub_key| {
                            self.record
                                .get(&hash)
                                .unwrap()
                                .entry
                                .verify(&signature, pub_key)
                        }) {
                            self.record.add_signature(&hash, src, signature);
                        }
                    }
                    if let State::Leader { ref mut last_hash, .. } = self.state {
                        // update the follower's last_hash
                        let current_last = last_hash
                            .get(&src)
                            .map_or(self.record.start_hash(), |hash| *hash);
                        let current_last_index = self.record.get_index(&current_last).unwrap_or(0);
                        let new_last_index = self.record.get_index(&hash).unwrap_or(0);
                        if new_last_index > current_last_index {
                            let _ = last_hash.insert(src, hash);
                        }
                    }
                    return self.commit_fully_signed();
                }
            }
            AppendEntriesResponse::Failure => {
                let resend = if let State::Leader { ref mut last_hash, .. } = self.state {
                    let current_last = last_hash
                        .get(&src)
                        .map_or(self.record.last_hash(), |hash| *hash);
                    let parent =
                        self.record
                            .get(&current_last)
                            .map_or(self.record.last_hash(), |entry| entry.entry.parent_hash);
                    last_hash.insert(src, parent);
                    true
                } else {
                    false
                };
                // can't resend inside the previous if because of last_hash being still borrowed
                // mutably
                if resend {
                    self.send_append_entries(net, src, false);
                }
            }
            AppendEntriesResponse::VotesRequired => self.send_append_entries(net, src, true),
        }
        Ok(Vec::new())
    }

    /// This method will be called when we don't receive heartbeats from the leader in a predefined
    /// time or when the previous election timed out. We then either start a new election, or vote
    /// for a node that started it already.
    fn handle_election_timeout<I: NetworkInterface<E>, S: Scheduler>(&mut self,
                                                                     net: &mut I,
                                                                     sched: &mut S) {
        match self.lazy_vote {
            None => {
                self.become_candidate(net, sched);
            }
            Some((term, candidate)) => {
                // we received RequestVote before - vote for the sender
                self.current_term = term;
                self.voted_for = Some(candidate);
                self.lazy_vote = None;
                if let Some(leader) = self.state.current_leader_mut() {
                    *leader = None;
                }
                self.send_vote_response(net, VoteResponseEnum::Granted, candidate);
                *(self.state.election_token_mut().unwrap()) = Self::restart_election_timer(sched);
            }
        }
    }

    /// This method will be invoked on the leader when it needs to send the next heartbeat message
    /// in order to maintain its leadership.
    fn handle_heartbeat_timeout<I: NetworkInterface<E>, S: Scheduler>(&mut self,
                                                                      net: &mut I,
                                                                      sched: &mut S) {
        if self.state.is_leader() {
            // broadcast heartbeats
            for peer in self.cluster.keys().filter(|&p| *p != self.our_id) {
                self.send_append_entries(net, *peer, true);
            }
            *self.state.heartbeat_token_mut().unwrap() = sched.schedule(HEARTBEAT_PERIOD);
        }
    }

    /// Generates a new random period to wait for a heartbeat and schedule a timeout.
    fn restart_election_timer<S: Scheduler>(sched: &mut S) -> TimerToken {
        let duration_range = Range::new(MIN_HEARTBEAT_RANGE, MAX_HEARTBEAT_RANGE);
        let mut rng = rand::thread_rng();
        let duration = duration_range.ind_sample(&mut rng);
        sched.schedule(duration)
    }

    /// Generates a `VoteResponse` for a given candidate along with a cryptographic signature.
    fn vote_for(&self,
                vote_granted: VoteResponseEnum,
                candidate: PeerId)
                -> (VoteResponse, sign::Signature) {
        let vote = VoteResponse {
            term: self.current_term,
            candidate: candidate,
            vote_granted: vote_granted,
        };
        let sig = vote.sign(&self.our_key);
        (vote, sig)
    }

    /// Sends a message requesting a vote from a follower.
    fn send_request_vote<I: NetworkInterface<E>>(&self,
                                                 net: &mut I,
                                                 dst: PeerId,
                                                 entries: Vec<SignedRecordEntry<E>>) {
        let request = Content::RequestVote(RequestVote {
                                               term: self.current_term,
                                               candidate_name: self.our_id,
                                               last_committed_hash: self.record.last_committed(),
                                               committed_entries: entries,
                                           });
        self.send_message(net, dst, request);
    }

    /// Sends the response to a vote request.
    fn send_vote_response<I: NetworkInterface<E>>(&self,
                                                  net: &mut I,
                                                  grant_vote: VoteResponseEnum,
                                                  candidate: PeerId) {
        let (vote, sig) = self.vote_for(grant_vote, candidate);
        let content = Content::VoteResponse {
            response: vote,
            response_sig: sig,
        };
        self.send_message(net, candidate, content);
    }

    /// Sends the `AppendEntries` message to `dst`, containing appropriate entries and a quorum of
    /// votes for us if `include_votes` is set.
    fn send_append_entries<I: NetworkInterface<E>>(&self,
                                                   net: &mut I,
                                                   dst: PeerId,
                                                   include_votes: bool) {
        if let State::Leader {
                   ref last_hash,
                   ref votes,
                   ..
               } = self.state {
            let entries = last_hash
                .get(&dst)
                .map_or_else(Vec::new, |hash| self.record.entries_since(hash));
            let prev_hash = *last_hash.get(&dst).unwrap_or(&Digest([0; 32]));
            let request: Content<E> =
                Content::AppendEntries(AppendEntries {
                                           term: self.current_term,
                                           entries: entries.into_iter().cloned().collect(),
                                           prev_log_hash: prev_hash,
                                           votes: if include_votes {
                                               votes.clone()
                                           } else {
                                               BTreeMap::new()
                                           },
                                       });
            self.send_message(net, dst, request);
        }
    }

    /// Sends the AppendEntriesResponse with the given result
    fn send_append_entries_response<I: NetworkInterface<E>>(&self,
                                                            net: &mut I,
                                                            dst: PeerId,
                                                            result: AppendEntriesResponse) {
        let request = Content::AppendEntriesResponse(result);
        self.send_message(net, dst, request);
    }

    /// Sends a message from us to `dst` with the given content.
    fn send_message<I: NetworkInterface<E>>(&self, net: &mut I, dst: PeerId, message: Content<E>) {
        let sig = message.signature(&self.our_key);
        let message = Message {
            src: self.our_id,
            dst: dst,
            content: message,
            signature: sig,
        };
        net.send_message(message);
    }

    /// Resets the uncommitted entries to agree with our pending entries.
    /// The uncommitted entries are kept until the point where they stop agreeing with what we have
    /// in pending entries. All entries after are deleted and new ones, corresponding to our
    /// pending ones, are appended.
    fn reset_uncommitted(&mut self) {
        let mut pending_copy = mem::replace(&mut self.pending_entries, HashSet::new());
        let mut last_agreeing_hash = self.record.last_hash();
        let mut to_sign = Vec::new();
        for entry in self.record
                .range(&self.record.last_committed(), &self.record.last_hash()) {
            if !pending_copy.contains(&entry.entry.entry) {
                last_agreeing_hash = entry.entry.parent_hash;
                break;
            }
            pending_copy.remove(&entry.entry.entry);
            // we agreed on this entry, so sign it afterwards
            to_sign.push(entry.entry.hash());
        }
        // sign the entries we have agreed on
        for hash in to_sign {
            self.record.sign(&hash, self.our_id, &self.our_key);
        }
        self.record.rewind(&last_agreeing_hash);
        for entry in pending_copy {
            let hash = self.record.append_entry(entry);
            self.record.sign(&hash, self.our_id, &self.our_key);
        }
    }

    /// Switches us to the `Leader` state and establishes our authority by broadcasting
    /// `AppendEntries`.
    fn become_leader<I: NetworkInterface<E>, S: Scheduler>(&mut self, net: &mut I, sched: &mut S) {
        if self.state.is_leader() {
            return;
        }
        info!("Node({:?}): Switching to Leader.", self.our_id);
        self.reset_uncommitted();
        let votes = self.state.votes().unwrap().clone();
        self.state = State::Leader {
            heartbeat_token: sched.schedule(HEARTBEAT_PERIOD),
            last_hash: self.cluster
                .keys()
                .map(|&key| (key, self.record.last_committed()))
                .collect(),
            votes: votes,
        };
        // broadcast heartbeats
        for peer in self.cluster.keys().filter(|&p| *p != self.our_id) {
            self.send_append_entries(net, *peer, true);
        }
    }

    /// Switches our state to `Candidate` and sends vote requests to other members of the cluster.
    fn become_candidate<I: NetworkInterface<E>, S: Scheduler>(&mut self,
                                                              net: &mut I,
                                                              sched: &mut S) {
        info!("Node({:?}): Switching to Candidate.", self.our_id);
        self.current_term += 1;
        let mut votes = BTreeMap::new();
        // vote for ourselves
        let vote = self.vote_for(VoteResponseEnum::Granted, self.our_id);
        self.voted_for = Some(self.our_id);
        votes.insert(self.our_id, vote);
        self.state = State::Candidate {
            votes: votes,
            election_token: Self::restart_election_timer(sched),
        };
        // broadcast RequestVote
        for peer in self.cluster.keys().filter(|&p| *p != self.our_id) {
            self.send_request_vote(net, *peer, Vec::new());
        }
    }

    /// Switches us to the `Follower` state.
    fn become_follower<S: Scheduler>(&mut self, sched: &mut S, leader: PeerId) {
        info!("Node({:?}): Now following Node({:?}).", self.our_id, leader);
        self.state = State::Follower {
            current_leader: Some(leader),
            election_token: Self::restart_election_timer(sched),
        };
    }
}

#[cfg(test)]
impl<E: Entry> ConsensusState<E> {
    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn current_term(&self) -> u64 {
        self.current_term
    }

    pub fn last_hash(&self) -> Digest {
        self.record.last_hash()
    }

    pub fn last_committed_hash(&self) -> Digest {
        self.record.last_committed()
    }
}
