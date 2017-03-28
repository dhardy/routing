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
use super::message::Message;
use super::record::Entry;

/// Allows sending of messages
pub trait NetworkInterface<E: Entry> {
    /// Send a message
    fn send_message(&mut self, msg: Message<E>);
}

/// Allows creation of timer tokens
pub trait Scheduler {
    /// Schedule a call to `ConsensusState::handle_timeout` after the elapsed `seconds` with a new
    /// `TimerToken`.
    fn schedule(&mut self, seconds: u64) -> TimerToken;
}
