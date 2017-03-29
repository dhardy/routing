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
use consensus::record::{Entry, RecordEntry};
use crust::PeerId;
use maidsafe_utilities::event_sender::MaidSafeEventCategory;
use rand;
use rand::distributions::{IndependentSample, LogNormal, Range};
use rust_sodium::crypto::sign;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::mem;
use std::sync::mpsc;
use std::time::Duration;
use timer::Timer;
use types::RoutingActionSender;

#[derive(Clone, Debug, PartialEq, Eq, RustcEncodable, Hash)]
pub enum TestEntry {
    Test,
}
impl Entry for TestEntry {}

struct MsgQueue<E: Entry> {
    pub timer: Timer,
    pub queued: HashMap<u64, Message<E>>,
    rng: rand::ThreadRng,
    dist: LogNormal,
}

impl<E: Entry> MsgQueue<E> {
    pub fn new(timer: Timer, randomize_msgs: bool) -> Self {
        // Standard deviation of 1 should produce most samples between 0.1 and 3
        let std_dev = if randomize_msgs { 1f64 } else { 0f64 };
        MsgQueue {
            timer: timer,
            queued: Default::default(),
            rng: rand::thread_rng(),
            dist: LogNormal::new(0f64, std_dev),
        }
    }
}

impl<E: Entry> NetworkInterface<E> for MsgQueue<E> {
    fn send_message(&mut self, msg: Message<E>) {
        let delay = self.dist.ind_sample(&mut self.rng);
        // approx. 5% chance delay is longer than 5, approx. 1% chance delay is longer than 10
        // (for mean 0, var 1: use logncdf(x) in Matlab/Octave)
        if delay > 10.0 {
            trace!("{:?} sends {:?} to {:?}; message lost",
                   msg.src,
                   msg.content,
                   msg.dst);
        } else {
            trace!("{:?} sends {:?} to {:?} with delay {:.2}s",
                   msg.src,
                   msg.content,
                   msg.dst,
                   delay);
            let dur = Duration::new(delay.trunc() as u64, (delay.fract() * 1e9) as u32);
            let token = self.timer.schedule(dur);
            self.queued.insert(token, msg);
        }
    }
}

pub struct Cluster {
    nodes: Vec<ConsensusState<TestEntry>>,
    msg_queue: MsgQueue<TestEntry>,
}

impl Cluster {
    pub fn new(num_nodes: usize, randomize_msgs: bool) -> Cluster {
        let mut secret_keys = vec![];
        let mut cluster_keys = BTreeMap::new();

        let (action_sender, _) = mpsc::channel();
        let (category_sender, _) = mpsc::channel();
        let routing_event_category = MaidSafeEventCategory::Routing;
        let sender = RoutingActionSender::new(action_sender,
                                              routing_event_category,
                                              category_sender.clone());
        let timer = Timer::new(sender);

        for i in 0..num_nodes {
            let (pub_key, priv_key) = sign::gen_keypair();
            secret_keys.push(priv_key);
            cluster_keys.insert(PeerId(i), pub_key);
        }
        let mut cluster = Vec::new();
        for (i, secret_key) in secret_keys.into_iter().enumerate() {
            let node =
                ConsensusState::new(PeerId(i), secret_key, cluster_keys.clone(), timer.clone());
            cluster.push(node);
        }

        Cluster {
            nodes: cluster,
            msg_queue: MsgQueue::new(timer, randomize_msgs),
        }
    }

    /// Run until some node commits one or more record entries.
    pub fn continue_until_entry(&mut self) -> (usize, Vec<RecordEntry<TestEntry>>) {
        let mut n_timers = 0;
        while let Some(token) = self.msg_queue.timer.get_next() {
            n_timers += 1;
            if n_timers > 1000 {
                // Sometimes test seems to loop forever. 1000 should be plenty.
                panic!("No result in 1000 timeouts");
            }

            if let Some(msg) = self.msg_queue.queued.remove(&token) {
                let dst = msg.dst.0;
                match self.nodes[dst].handle_message(msg, &mut self.msg_queue) {
                    Ok(entries) => {
                        if entries.len() > 0 {
                            return (dst, entries);
                        }
                    }
                    Err(e) => panic!("handle_message on node {} failed: {:?}", dst, e),
                };
            } else {
                // We don't know which node this is for, but it will be unique. Send to all.
                for ref mut node in &mut self.nodes {
                    node.handle_timeout(token, &mut self.msg_queue);
                }
            }
        }
        // We never get here because each node schedules heartbeats forever
        panic!("No timeouts left");
    }

    pub fn propose_entry(&mut self, name: usize, entry: RecordEntry<TestEntry>) {
        let _ = self.nodes[name].propose_entry(&mut self.msg_queue, entry);
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
    #[ignore] // TODO: sometimes fails
    fn test_elect_leader() {
        let _ = maidsafe_utilities::log::init(false);
        let mut cluster = Cluster::new(8, true);

        for i in 0..6 {
            cluster.propose_entry(i, RecordEntry::Regular(TestEntry::Test));
        }
        print_cluster_states(&cluster);
        let (node, entries) = cluster.continue_until_entry();
        for (i, entry) in entries.iter().enumerate() {
            debug!("Node {} committed entry {}: {:?}", node, i, entry);
        }
    }
}
