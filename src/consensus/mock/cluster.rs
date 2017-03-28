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

use consensus::{ConsensusState, NetworkInterface};
use consensus::message::Message;
use consensus::mock::Timers;
use consensus::record::{Entry, RecordEntry};
use crust::PeerId;
use rand;
use rand::distributions::{IndependentSample, Range};
use rust_sodium::crypto::sign;
use std::collections::{BTreeMap, VecDeque};
use std::mem;

#[derive(Clone, PartialEq, Eq, RustcEncodable, Hash)]
pub enum TestEntry {
    Test,
}
impl Entry for TestEntry {}

pub struct Cluster {
    nodes: Vec<ConsensusState<TestEntry>>,
    timers: Timers,
    msg_queue: VecDeque<Message<TestEntry>>,
    randomize_msgs: bool,
    rng: rand::ThreadRng,
}

impl Cluster {
    pub fn new(num_nodes: usize, randomize_msgs: bool) -> Cluster {
        let mut secret_keys = vec![];
        let mut cluster_keys = BTreeMap::new();
        let mut timers = Timers::new();
        for i in 0..num_nodes {
            let (pub_key, priv_key) = sign::gen_keypair();
            secret_keys.push(priv_key);
            cluster_keys.insert(PeerId(i), pub_key);
        }
        let mut cluster = Vec::new();
        for (i, secret_key) in secret_keys.into_iter().enumerate() {
            let node = ConsensusState::new(PeerId(i),
                                           secret_key,
                                           cluster_keys.clone(),
                                           &mut timers.get_timer_for(i));
            cluster.push(node);
        }
        Cluster {
            nodes: cluster,
            timers: timers,
            msg_queue: VecDeque::new(),
            randomize_msgs: randomize_msgs,
            rng: rand::thread_rng(),
        }
    }

    pub fn deliver_msgs(&mut self) {
        let mut old_queue = mem::replace(&mut self.msg_queue, VecDeque::new());
        while !old_queue.is_empty() {
            let msg = if self.randomize_msgs {
                let index = Range::new(0, old_queue.len()).ind_sample(&mut self.rng);
                old_queue.remove(index).unwrap()
            } else {
                old_queue.pop_front().unwrap()
            };
            let dst = msg.dst.0;
            let _ = self.nodes[dst].handle_message(msg,
                                                   &mut self.msg_queue,
                                                   &mut self.timers.get_timer_for(dst));
        }
    }

    pub fn deliver_msgs_until_empty(&mut self) {
        while !self.msg_queue.is_empty() {
            self.deliver_msgs();
        }
    }

    pub fn tick(&mut self) -> bool {
        let timeouts = self.timers.tick();
        let result = !timeouts.is_empty();
        for (name, token) in timeouts {
            self.nodes[name].handle_timeout(token,
                                            &mut self.msg_queue,
                                            &mut self.timers.get_timer_for(name));
        }
        result
    }

    pub fn tick_until_timeout(&mut self) {
        while !self.tick() {}
    }

    pub fn propose_entry(&mut self, name: usize, entry: RecordEntry<TestEntry>) {
        let _ = self.nodes[name].propose_entry(&mut self.msg_queue, entry);
    }
}

impl<E: Entry> NetworkInterface<E> for VecDeque<Message<E>> {
    fn send_message(&mut self, msg: Message<E>) {
        trace!("{:?} sends {:?} to {:?}", msg.src, msg.content, msg.dst);
        self.push_back(msg);
    }
}

#[cfg(test)]
mod test {
    use super::{Cluster, RecordEntry, TestEntry};
    use consensus::PrintableDigest;
    use consensus::state::State;
    use maidsafe_utilities;

    fn print_cluster_states(cluster: &Cluster) {
        debug!("-----------------------");
        debug!("Node states:");
        for (i, node) in cluster.nodes.iter().enumerate() {
            match *node.state() {
                State::Candidate { ref votes, .. } => {
                    debug!("{}: Candidate (term={}, {} votes)",
                           i,
                           node.current_term(),
                           votes.len())
                }
                State::Follower { .. } => {
                    debug!("{}: Follower (term={}, log: \
                            last={:?}/comm={:?})",
                           i,
                           node.current_term(),
                           PrintableDigest(node.last_hash()),
                           PrintableDigest(node.last_committed_hash()));
                }
                State::Leader { ref votes, .. } => {
                    debug!("{}: Leader (term={}, {} votes; log: \
                            last={:?}/comm={:?})",
                           i,
                           node.current_term(),
                           votes.len(),
                           PrintableDigest(node.last_hash()),
                           PrintableDigest(node.last_committed_hash()));
                }
            }
        }
        debug!("-----------------------");
    }

    #[test]
    fn test_elect_leader() {
        let _ = maidsafe_utilities::log::init(false);
        let mut cluster = Cluster::new(8, true);
        for _ in 0..10 {
            cluster.tick_until_timeout();
            cluster.deliver_msgs_until_empty();
            print_cluster_states(&cluster);
        }
        for i in 0..6 {
            cluster.propose_entry(i, RecordEntry::Regular(TestEntry::Test));
        }
        for _ in 0..10 {
            cluster.tick_until_timeout();
            cluster.deliver_msgs_until_empty();
            print_cluster_states(&cluster);
        }
    }
}
