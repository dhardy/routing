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

use crust::PeerId;
use event::Event;
use std::default::Default;
use std::mem;

//TODO: use actual messages
pub struct Message;


/// Trait to convert to an EventTray
pub trait AsEventTray {
    /// Convert to an EventTray
    fn as_evt(&mut self) -> &mut EventTray;
}

/// An event dispatcher. Collects things to deliver and "sends".
///
/// The API doesn't specify whether objects get sent immediately synchronously or asynchronously,
/// or collected and sent later.
pub trait EventTray: AsEventTray {
    /// Send an event
    fn send_event(&mut self, event: Event);

    /// Send a `Vec` of events
    fn send_events(&mut self, events: Vec<Event>);
}


/// A box implenting `EventTray` by collecting items to send later.
#[must_use]
#[derive(Default)]
pub struct EventBox {
    events: Vec<Event>,
}

impl EventBox {
    /// Create an empty box
    pub fn new() -> Self {
        Default::default()
    }

    /// Extract the list of events (swapping in an empty list)
    pub fn take_events(&mut self) -> Vec<Event> {
        mem::replace(&mut self.events, vec![])
    }
}

impl Drop for EventBox {
    fn drop(&mut self) {
        // All events should be handled before this is dropped
        if !self.events.is_empty() {
            error!("Events were dropped: {} events", self.events.len());
        }
    }
}

impl EventTray for EventBox {
    fn send_event(&mut self, event: Event) {
        self.events.push(event)
    }

    fn send_events(&mut self, events: Vec<Event>) {
        self.events.extend(events)
    }
}


/// A message dispatcher. Collects things to deliver and "sends".
///
/// This collects several pieces of functionality needed for routing.
///
/// The API doesn't specify whether objects get sent immediately synchronously or asynchronously,
/// or collected and sent later.
#[must_use]
#[derive(Default)]
pub struct OutTray {
    events: Vec<Event>,
    to_disconnect: Vec<PeerId>,
    messages: Vec<Message>,
}

impl OutTray {
    /// Create an empty box
    pub fn new() -> Self {
        Default::default()
    }

    /// Schedule a disconnect from this peer.
    pub fn disconnect(&mut self, peer: &PeerId) {
        self.to_disconnect.push(*peer)
    }

    /// Schedule disconnection from all these peers.
    pub fn disconnect_all(&mut self, peers: Vec<PeerId>) {
        self.to_disconnect.extend(peers)
    }

    /// Send a message
    #[allow(unused)]
    pub fn send_msg(&mut self, msg: Message) {
        self.messages.push(msg)
    }

    /// Send a `Vec` of messages
    #[allow(unused)]
    pub fn send_msgs(&mut self, messages: Vec<Message>) {
        self.messages.extend(messages)
    }

    /// Extract the list of events (swapping in an empty list)
    pub fn take_events(&mut self) -> Vec<Event> {
        mem::replace(&mut self.events, vec![])
    }

    /// Extract the list of peers to disconnect from (swapping in an empty list)
    pub fn take_to_disconnect(&mut self) -> Vec<PeerId> {
        mem::replace(&mut self.to_disconnect, vec![])
    }

    /// Extract the list of messages (swapping in an empty list)
    #[allow(unused)]
    pub fn take_messages(&mut self) -> Vec<Message> {
        mem::replace(&mut self.messages, vec![])
    }
}

impl Drop for OutTray {
    fn drop(&mut self) {
        // All items should be handled before this is dropped
        if !self.events.is_empty() || !self.messages.is_empty() || !self.to_disconnect.is_empty() {
            error!("Items were dropped: {} events, {} messages, {} disconnect commands",
                   self.events.len(),
                   self.messages.len(),
                   self.to_disconnect.len());
        }
    }
}

impl EventTray for OutTray {
    fn send_event(&mut self, event: Event) {
        self.events.push(event)
    }

    fn send_events(&mut self, events: Vec<Event>) {
        self.events.extend(events)
    }
}

impl<T: EventTray> AsEventTray for T {
    fn as_evt(&mut self) -> &mut EventTray {
        self
    }
}
