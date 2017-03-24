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

use rust_sodium::crypto::hash::sha256::Digest;
use rust_sodium::crypto::sign::Signature;
use std::fmt;

pub struct PrintableDigest(pub Digest);

impl fmt::Debug for PrintableDigest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = &(self.0).0;
        write!(f, "{:02x}{:02x}{:02x}..", bytes[0], bytes[1], bytes[2])
    }
}

pub struct PrintableSignature(pub Signature);

impl fmt::Debug for PrintableSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = &(self.0).0;
        write!(f, "{:02x}{:02x}{:02x}..", bytes[0], bytes[1], bytes[2])
    }
}
