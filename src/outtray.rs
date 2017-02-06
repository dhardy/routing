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

use event::Event;
use evented::Evented;
use std::default::Default;
use std::mem;

//TODO: use actual messages
pub struct Message;


/// An event dispatcher. Collects things to deliver and "sends".
///
/// The API doesn't specify whether objects get sent immediately synchronously or asynchronously,
/// or collected and sent later.
pub trait EventTray {
    /// Send an event
    fn send_event(&mut self, event: Event);

    /// Send a `Vec` of events
    fn send_events(&mut self, events: Vec<Event>);
}

/// A message dispatcher. Collects things to deliver and "sends".
///
/// The API doesn't specify whether objects get sent immediately synchronously or asynchronously,
/// or collected and sent later.
pub trait MessageTray {
    /// Send a message
    fn send_msg(&mut self, msg: Message);

    /// Send a `Vec` of messages
    fn send_msgs(&mut self, messages: Vec<Message>);
}

/// Combination of all out-trays
pub trait OutTray: EventTray + MessageTray {}


/// A box implenting `OutTray` by collecting items to send later.
#[derive(Default)]
pub struct OutBox {
    events: Vec<Event>,
}

impl OutBox {
    /// Create an empty box
    pub fn new() -> Self {
        Default::default()
    }

    /// Extract the list of events (swapping in an empty list)
    //TODO: do we need this?
    #[allow(unused)]
    pub fn take_events(&mut self) -> Vec<Event> {
        mem::replace(&mut self.events, vec![])
    }

    /// Convert to an Evented<()>
    ///
    /// Note: chain .with_value to add another value
    pub fn to_evented(self) -> Evented<()> {
        Evented::empty_with_events(self.events)
    }
}

impl EventTray for OutBox {
    fn send_event(&mut self, event: Event) {
        self.events.push(event)
    }

    fn send_events(&mut self, events: Vec<Event>) {
        self.events.extend(events)
    }
}

impl MessageTray for OutBox {
    fn send_msg(&mut self, _msg: Message) {
        unimplemented!()
    }
    fn send_msgs(&mut self, _messages: Vec<Message>) {
        unimplemented!()
    }
}

impl OutTray for OutBox {}
