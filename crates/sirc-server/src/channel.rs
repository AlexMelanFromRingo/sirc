//! Channel management

use std::collections::HashSet;

pub struct Channel {
    pub name: String,
    pub topic: Option<String>,
    pub members: HashSet<String>,
}

impl Channel {
    pub fn new(name: String) -> Self {
        Self {
            name,
            topic: None,
            members: HashSet::new(),
        }
    }

    pub fn add_member(&mut self, nick: String) {
        self.members.insert(nick);
    }

    pub fn remove_member(&mut self, nick: &str) {
        self.members.remove(nick);
    }

    pub fn has_member(&self, nick: &str) -> bool {
        self.members.contains(nick)
    }

    pub fn set_topic(&mut self, topic: Option<String>) {
        self.topic = topic;
    }

    /// Channel name (for diagnostics / logging).
    pub fn name(&self) -> &str {
        &self.name
    }
}
