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

// TODO: remove this when code is used
#![allow(unused)]

// TODO: can can we allow this globally? Pretty please?
#![allow(unused_results)]

pub mod record;
pub mod message;
pub mod state;
pub mod consensus_state;
mod interface;
mod error;
mod printable;

#[cfg(test)]
mod mock;

pub use self::consensus_state::ConsensusState;
pub use self::error::Error;
pub use self::interface::{NetworkInterface, Scheduler};
pub use self::printable::{PrintableDigest, PrintableSignature};

use rustc_serialize::Encodable;
use std::fmt::Debug;
use std::hash::Hash;

pub trait PeerId: Copy + Ord + Encodable + Debug + Hash {}
pub type TimerToken = u64;
