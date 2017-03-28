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
use super::message::VoteResponse;
use crust::PeerId;
use rust_sodium::crypto::hash::sha256::Digest;
use rust_sodium::crypto::sign;
use std::collections::{BTreeMap, HashMap};

pub type Votes = BTreeMap<PeerId, (VoteResponse, sign::Signature)>;

pub enum State {
    Follower {
        election_token: TimerToken,
        current_leader: Option<PeerId>,
    },
    Candidate {
        votes: Votes,
        election_token: TimerToken,
    },
    Leader {
        // index of the next log entry to be sent to each node (initialized to our last index + 1)
        last_hash: HashMap<PeerId, Digest>,
        // used to prove leadership
        votes: Votes,
        heartbeat_token: TimerToken,
    },
}

pub enum TokenMatch {
    Election,
    Heartbeat,
    None,
}

impl State {
    /// Returns whether the state is `Follower`.
    pub fn is_follower(&self) -> bool {
        if let State::Follower { .. } = *self {
            true
        } else {
            false
        }
    }

    /// Returns whether the state is `Candidate`.
    pub fn is_candidate(&self) -> bool {
        if let State::Candidate { .. } = *self {
            true
        } else {
            false
        }
    }

    /// Returns whether the state is `Leader`.
    pub fn is_leader(&self) -> bool {
        if let State::Leader { .. } = *self {
            true
        } else {
            false
        }
    }

    /// Returns the stored votes for us (if existing).
    pub fn votes(&self) -> Option<&Votes> {
        match *self {
            State::Candidate { ref votes, .. } |
            State::Leader { ref votes, .. } => Some(votes),
            _ => None,
        }
    }

    /// Returns a mutable reference to the set of stored votes (if existing).
    pub fn votes_mut(&mut self) -> Option<&mut Votes> {
        match *self {
            State::Candidate { ref mut votes, .. } |
            State::Leader { ref mut votes, .. } => Some(votes),
            _ => None,
        }
    }

    /// Returns a mutable reference to the token for the timer controlling heartbeats.
    pub fn heartbeat_token_mut(&mut self) -> Option<&mut TimerToken> {
        if let State::Leader { ref mut heartbeat_token, .. } = *self {
            Some(heartbeat_token)
        } else {
            None
        }
    }

    /// Returns a mutable reference to the token for the timer controlling elections.
    pub fn election_token_mut(&mut self) -> Option<&mut TimerToken> {
        match *self {
            State::Follower { ref mut election_token, .. } |
            State::Candidate { ref mut election_token, .. } => Some(election_token),
            _ => None,
        }
    }

    /// Checks whether the given token matches any in our state.
    pub fn check_token(&self, token: TimerToken) -> TokenMatch {
        match *self {
            State::Follower { election_token, .. } |
            State::Candidate { election_token, .. } => {
                if token == election_token {
                    TokenMatch::Election
                } else {
                    TokenMatch::None
                }
            }
            State::Leader { heartbeat_token, .. } => {
                if token == heartbeat_token {
                    TokenMatch::Heartbeat
                } else {
                    TokenMatch::None
                }
            }
        }
    }

    /// Returns the name of the current leader.
    pub fn current_leader(&self) -> Option<PeerId> {
        if let State::Follower { current_leader, .. } = *self {
            current_leader
        } else {
            None
        }
    }

    /// Returns a mutable reference to the name of the current leader.
    pub fn current_leader_mut(&mut self) -> Option<&mut Option<PeerId>> {
        if let State::Follower { ref mut current_leader, .. } = *self {
            Some(current_leader)
        } else {
            None
        }
    }
}
