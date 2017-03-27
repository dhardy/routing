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

use consensus::{Scheduler, TimerToken};
use std::collections::HashMap;

pub struct Timers {
    current_tick: u64,
    next_token: TimerToken,
    timers: HashMap<u64, Vec<(usize, TimerToken)>>,
}

impl Timers {
    pub fn new() -> Timers {
        Timers {
            current_tick: 0,
            next_token: 0,
            timers: HashMap::new(),
        }
    }

    pub fn tick(&mut self) -> Vec<(usize, TimerToken)> {
        let result = if let Some(tokens) = self.timers.remove(&self.current_tick) {
            tokens
        } else {
            Vec::new()
        };
        self.current_tick += 1;
        result
    }

    fn schedule(&mut self, name: usize, duration: u64) -> TimerToken {
        self.next_token += 1;
        let timeout = self.current_tick + duration;
        self.timers
            .entry(timeout)
            .or_insert_with(Vec::new)
            .push((name, self.next_token));
        self.next_token
    }

    pub fn get_timer_for<'a>(&'a mut self, name: usize) -> PersonalizedTimer<'a> {
        PersonalizedTimer {
            name: name,
            timer: self,
        }
    }
}

pub struct PersonalizedTimer<'a> {
    name: usize,
    timer: &'a mut Timers,
}

impl<'a> Scheduler for PersonalizedTimer<'a> {
    fn schedule(&mut self, duration: u64) -> TimerToken {
        self.timer.schedule(self.name, duration)
    }
}
