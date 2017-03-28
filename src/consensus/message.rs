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

use super::{PrintableDigest, PrintableSignature};
use super::record::{Entry, SignedRecordEntry};
use super::state::Votes;
use crust::PeerId;
use maidsafe_utilities::serialisation;
use rust_sodium::crypto::hash::sha256::Digest;
use rust_sodium::crypto::sign;
use std::fmt;

/// Encapsulation of message sender, recipient, content and signature.
pub struct Message<E: Entry> {
    pub src: PeerId,
    pub dst: PeerId,
    pub content: Content<E>,
    pub signature: sign::Signature,
}

/// Content of messages sent between nodes.
#[derive(Clone, RustcEncodable)]
pub enum Content<E: Entry> {
    AppendEntries(AppendEntries<E>),
    AppendEntriesResponse(AppendEntriesResponse),
    RequestVote(RequestVote<E>),
    VoteResponse {
        response: VoteResponse,
        response_sig: sign::Signature,
    },
    // TODO: add fields 'event: LogEntry' and 'signature'
    DoubtLeader { term: u64, leader_name: PeerId },
}

impl<E: Entry> Content<E> {
    /// Signs the message content with a given key.
    pub fn signature(&self, key: &sign::SecretKey) -> sign::Signature {
        let bytes = serialisation::serialise(self)
            .ok()
            .expect("Message content serialisation failure");
        sign::sign_detached(&bytes, key)
    }

    /// Verifies the content signature.
    pub fn verify(&self, sig: &sign::Signature, key: &sign::PublicKey) -> bool {
        let bytes = serialisation::serialise(self)
            .ok()
            .expect("Message content serialisation failure");
        sign::verify_detached(sig, &bytes, key)
    }
}

impl<E: Entry> fmt::Debug for Content<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Content::AppendEntries(ref ae) => {
                write!(formatter,
                       "AppendEntries(term = {}, prev_log_hash = {:?}, entries = {:?})",
                       ae.term,
                       PrintableDigest(ae.prev_log_hash),
                       ae.entries
                           .iter()
                           .map(|entry| PrintableDigest(entry.entry.hash()))
                           .collect::<Vec<_>>())
            }
            Content::AppendEntriesResponse(result) => {
                write!(formatter, "AppendEntriesResponse({:?})", result)
            }
            Content::RequestVote(ref req) => {
                write!(formatter,
                       "RequestVote(term = {}, candidate = {:?}, last_committed_hash = {:?})",
                       req.term,
                       req.candidate_name,
                       PrintableDigest(req.last_committed_hash))
            }
            Content::VoteResponse { response, .. } => {
                write!(formatter,
                       "VoteResponse(term = {}, candidate = {:?}, vote_granted = {:?})",
                       response.term,
                       response.candidate,
                       response.vote_granted)
            }
            Content::DoubtLeader { .. } => write!(formatter, "DoubtLeader"),
        }
    }
}

#[derive(Clone, RustcEncodable)]
pub struct AppendEntries<E: Entry> {
    pub term: u64,
    pub prev_log_hash: Digest,
    pub entries: Vec<SignedRecordEntry<E>>,
    pub votes: Votes,
}

#[derive(Clone, Copy, RustcEncodable)]
pub enum AppendEntriesResponse {
    Success {
        hash: Digest,
        signature: Option<sign::Signature>,
    },
    Failure,
    VotesRequired,
}

impl fmt::Debug for AppendEntriesResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AppendEntriesResponse::Success {
                hash,
                ref signature,
            } => {
                write!(formatter,
                       "Success({:?}, sig: {:?})",
                       PrintableDigest(hash),
                       signature.and_then(|sig| Some(PrintableSignature(sig))))
            }
            AppendEntriesResponse::Failure => write!(formatter, "Failure"),
            AppendEntriesResponse::VotesRequired => write!(formatter, "VotesRequired"),
        }
    }
}

#[derive(Clone, RustcEncodable)]
pub struct RequestVote<E: Entry> {
    pub term: u64,
    pub candidate_name: PeerId,
    pub last_committed_hash: Digest,
    pub committed_entries: Vec<SignedRecordEntry<E>>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, RustcEncodable, Clone, Copy, Debug)]
pub enum VoteResponseEnum {
    Granted,
    Denied,
    RequestProof { last_committed: Digest },
}

#[derive(PartialEq, Eq, PartialOrd, Ord, RustcEncodable, Clone, Copy)]
pub struct VoteResponse {
    pub term: u64,
    pub candidate: PeerId,
    pub vote_granted: VoteResponseEnum,
}

impl VoteResponse {
    /// Generates a signature for a `VoteResponse` - needed during elections.
    pub fn sign(&self, key: &sign::SecretKey) -> sign::Signature {
        let bytes = serialisation::serialise(self)
            .ok()
            .expect("VoteResponse serialisation error!");
        sign::sign_detached(&bytes, key)
    }

    /// Verifies the vote signature.
    pub fn verify_sig(&self, sig: sign::Signature, key: &sign::PublicKey) -> bool {
        let bytes = serialisation::serialise(self)
            .ok()
            .expect("VoteResponse serialisation error!");
        sign::verify_detached(&sig, &bytes, key)
    }
}
