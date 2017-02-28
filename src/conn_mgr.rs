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


use XorName;

use crust::{CrustError, Service};

use std::fmt::{self, Debug};

/// Manages connections via Crust
pub struct ConnManager {
    // TODO: do we need to keep a redundant copy of the name?
    name: XorName,
    service: Service,
}

impl ConnManager {
    /// Create, given a name and Crust service
    pub fn new(name: XorName, service: Service) -> Self {
        ConnManager {
            name: name,
            service: service,
        }
    }

    /// Starts accepting TCP connections. This just wraps the Crust `Service` function by the same
    /// name.
    pub fn start_listening_tcp(&mut self) -> Result<(), CrustError> {
        self.service.start_listening_tcp()
    }

    /// Get direct access to the Crust service. TODO: remove this when possible.
    pub fn crust_service(&self) -> &Service {
        &self.service
    }

    fn name(&self) -> &XorName {
        &self.name
    }
}

impl Debug for ConnManager {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Node({}::ConnMgr)", self.name())
    }
}
