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
use crust::{CrustError, PeerId, Service};
use crust::Event as CrustEvent;
use event::Event;
use id::PublicId;
use outbox::EventBox;
use rand;
use state_machine::Transition;
use std::collections::HashMap;
use std::fmt::{self, Debug};

/// Manages connections via Crust
pub struct ConnManager {
    // TODO: do we need to keep a redundant copy of the name?
    name: XorName,
    service: Service,
    connection_tokens: HashMap<u32, PublicId>,
}

// first impl: constructors and simple getters and setters
impl ConnManager {
    /// Create, given a name and Crust service
    pub fn new(name: XorName, service: Service) -> Self {
        ConnManager {
            name: name,
            service: service,
            connection_tokens: HashMap::new(),
        }
    }

    /// Get direct access to the Crust service. TODO: remove this when possible.
    pub fn crust_service(&self) -> &Service {
        &self.service
    }

    /// Get our `PeerId`
    pub fn id(&self) -> PeerId {
        self.service.id()
    }

    /// Add a connection token. TODO: remove this when possible.
    pub fn add_conn_token(&mut self, token: u32, pub_id: PublicId) {
        let _old: Option<PublicId> = self.connection_tokens.insert(token, pub_id);
    }

    /// Remove a connection token. TODO: remove this when possible.
    pub fn remove_conn_token(&mut self, token: u32) -> Option<PublicId> {
        self.connection_tokens.remove(&token)
    }

    fn name(&self) -> &XorName {
        &self.name
    }
}

// second impl: the rest
impl ConnManager {
    /// Starts accepting TCP connections. This just wraps the Crust `Service` function by the same
    /// name.
    pub fn start_listening_tcp(&mut self) -> Result<(), CrustError> {
        self.service.start_listening_tcp()
    }

    /// Handles a subset of Crust events
    pub fn handle_event(&mut self, event: CrustEvent, outbox: &mut EventBox) -> Transition {
        use self::CrustEvent::*;
        match event {
            ListenerStarted(port) => {
                trace!("{:?} Listener started on port {}.", self, port);
                self.service.set_service_discovery_listen(true);
            }
            ListenerFailed => {
                error!("{:?} Failed to start listening.", self);
                outbox.send_event(Event::Terminate);
                return Transition::Terminate;
            }
            WriteMsgSizeProhibitive(peer_id, msg) => {
                error!("{:?} Failed to send {}-byte message to {:?}. Message too large.",
                       self,
                       msg.len(),
                       peer_id);
            }
            event => {
                debug!("{:?} Unhandled crust event: {:?}", self, event);
            }
        }
        Transition::Stay
    }

    /// If preparing connection info failed with the given token, prepares and returns a new token.
    pub fn make_new_connection_info_token(&mut self, token: u32) {
        if let Some(pub_id) = self.remove_conn_token(token) {
            let new_token = rand::random();
            self.add_conn_token(new_token, pub_id);
            self.service.prepare_connection_info(new_token);
            return;
        }

        debug!("{:?} Failed to prepare connection info, but no entry found in token map",
               self);
    }
}

impl Debug for ConnManager {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Node({}::ConnMgr)", self.name())
    }
}
