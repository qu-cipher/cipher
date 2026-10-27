//! Everything the app remembers between runs, saved as `state.json` in the data dir.

use crate::engine::paths;
use crate::import::{Subscription, Usage};
use crate::plugin::TransportUse;
use crate::profile::{Profile, PsiphonSource, Settings};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const FILE_NAME: &str = "state.json";

/// A profile with an id that stays stable across runs (used for selection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: u64,
    pub profile: Profile,
    /// A transport plugin this config runs through (see `crate::plugin`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportUse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSubscription {
    pub id: u64,
    pub name: String,
    pub url: String,
    pub usage: Option<Usage>,
    /// Unix timestamp of the last successful update.
    pub updated_at: Option<u64>,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Store {
    pub settings: Settings,
    /// Configs added by hand (links, files).
    pub manual: Vec<Entry>,
    pub subscriptions: Vec<StoredSubscription>,
    pub selected: Option<u64>,
    next_id: u64,

    #[serde(skip)]
    path: Option<PathBuf>,
}

impl Store {
    /// Loads the saved state. A missing file gives an empty store; a corrupt one is
    /// moved aside to `state.json.bak` instead of being overwritten.
    pub fn load() -> Self {
        let Ok(path) = paths::data_dir().map(|dir| dir.join(FILE_NAME)) else {
            return Self::default();
        };

        let mut store = match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).map(|store: Store| store.migrated(&text)).unwrap_or_else(|e| {
                eprintln!("state.json is unreadable ({e}), starting fresh");
                let _ = fs::rename(&path, path.with_extension("json.bak"));
                Self::default()
            }),
            Err(_) => Self::default(),
        };
        store.path = Some(path);
        store
    }

    /// Writes atomically (temp file + rename). The file holds credentials,
    /// so on Unix it is only readable by the user.
    pub fn save(&self) -> io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let tmp = path.with_extension("json.tmp");
        paths::write_private(&tmp, &serde_json::to_string_pretty(self)?)?;
        fs::rename(tmp, path)
    }

    /// Up to 0.3: one Psiphon network config in `settings.psiphon.network`, used by a built-in
    /// entry (id 0). It becomes a normal config; the old field isn't saved again.
    fn migrated(mut self, text: &str) -> Self {
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct Old { settings: OldSettings }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct OldSettings { psiphon: OldPsiphon }
        #[derive(Deserialize, Default)]
        #[serde(default)]
        struct OldPsiphon { network: Option<serde_json::Map<String, serde_json::Value>> }

        if let Ok(Old { settings: OldSettings { psiphon: OldPsiphon { network: Some(network) } } }) = serde_json::from_str(text) {
            let name = "Psiphon (imported config)".into();
            self.add_profiles(vec![Profile::Psiphon { name, source: PsiphonSource::Network(network) }]);
        }
        // Android has no system proxy setting to change.
        #[cfg(target_os = "android")]
        if self.settings.mode == crate::profile::ConnectionMode::SystemProxy {
            self.settings.mode = crate::profile::ConnectionMode::Tunnel;
        }
        self.forget_missing_selection();
        self
    }

    fn next_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    fn entries_from(&mut self, profiles: Vec<Profile>) -> Vec<Entry> {
        profiles.into_iter().map(|profile| Entry { id: self.next_id(), profile, transport: None }).collect()
    }

    /// Adds manual configs and returns their ids.
    pub fn add_profiles(&mut self, profiles: Vec<Profile>) -> Vec<u64> {
        let entries = self.entries_from(profiles);
        let ids = entries.iter().map(|e| e.id).collect();
        self.manual.extend(entries);
        ids
    }

    pub fn add_subscription(&mut self, url: &str, content: Subscription) -> u64 {
        let id = self.next_id();
        let name = content.title.clone().unwrap_or_else(|| host_of(url));
        let entries = self.entries_from(content.profiles);
        self.subscriptions.push(StoredSubscription {
            id,
            name,
            url: url.trim().to_owned(),
            usage: content.usage,
            updated_at: Some(now()),
            entries,
        });
        id
    }

    /// Replaces a subscription's configs. If the selected config came from it, the selection
    /// moves to the new config with the same name (servers usually keep their names); so do
    /// the transports chosen for its configs.
    pub fn update_subscription(&mut self, id: u64, content: Subscription) {
        let Some(index) = self.subscriptions.iter().position(|s| s.id == id) else { return };
        let mut entries = self.entries_from(content.profiles);

        let subscription = &mut self.subscriptions[index];
        for entry in &mut entries {
            let old = subscription.entries.iter().find(|e| e.profile.name() == entry.profile.name());
            entry.transport = old.and_then(|e| e.transport.clone());
        }
        let selected_name = self
            .selected
            .and_then(|sel| subscription.entries.iter().find(|e| e.id == sel))
            .map(|e| e.profile.name().to_owned());
        if let Some(name) = selected_name {
            self.selected = entries.iter().find(|e| e.profile.name() == name).map(|e| e.id);
        }

        subscription.entries = entries;
        subscription.updated_at = Some(now());
        if content.usage.is_some() {
            subscription.usage = content.usage;
        }
        if let Some(title) = content.title {
            subscription.name = title;
        }
    }

    pub fn remove_subscription(&mut self, id: u64) {
        self.subscriptions.retain(|s| s.id != id);
        self.forget_missing_selection();
    }

    pub fn remove_entry(&mut self, id: u64) {
        self.manual.retain(|e| e.id != id);
        for subscription in &mut self.subscriptions {
            subscription.entries.retain(|e| e.id != id);
        }
        self.forget_missing_selection();
    }

    pub fn entry_mut(&mut self, id: u64) -> Option<&mut Entry> {
        self.manual
            .iter_mut()
            .chain(self.subscriptions.iter_mut().flat_map(|s| s.entries.iter_mut()))
            .find(|e| e.id == id)
    }

    pub fn entry(&self, id: u64) -> Option<&Entry> {
        self.all_entries().find(|(_, e)| e.id == id).map(|(_, e)| e)
    }

    /// Every config with the subscription it belongs to (`None` = manual).
    pub fn all_entries(&self) -> impl Iterator<Item = (Option<&StoredSubscription>, &Entry)> {
        let manual = self.manual.iter().map(|e| (None, e));
        let subscribed = self
            .subscriptions
            .iter()
            .flat_map(|s| s.entries.iter().map(move |e| (Some(s), e)));
        manual.chain(subscribed)
    }

    fn forget_missing_selection(&mut self) {
        if let Some(id) = self.selected && self.entry(id).is_none() {
            self.selected = None;
        }
    }
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// `https://sub.example.com/abc` → `sub.example.com`, as a default subscription name.
fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = host.rsplit_once('@').map_or(host, |(_, host)| host);
    host.split(':').next().unwrap_or(host).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::parse_link;

    fn subscription(names: &[&str]) -> Subscription {
        Subscription {
            profiles: names
                .iter()
                .map(|name| parse_link(&format!("trojan://pw@{name}.example.com:443#{name}")).unwrap())
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn update_keeps_selection_by_name() {
        let mut store = Store::default();
        let sub = store.add_subscription("https://user@sub.example.com:8443/x?token=1", subscription(&["DE", "NL"]));
        assert_eq!(store.subscriptions[0].name, "sub.example.com");

        let nl = store.subscriptions[0].entries[1].id;
        store.selected = Some(nl);

        store.update_subscription(sub, subscription(&["US", "NL"]));
        let new_nl = store.subscriptions[0].entries[1].id;
        assert_ne!(new_nl, nl);
        assert_eq!(store.selected, Some(new_nl));

        store.update_subscription(sub, subscription(&["US"]));
        assert_eq!(store.selected, None);
    }

    #[test]
    fn update_keeps_transports_by_name() {
        let mut store = Store::default();
        let id = store.add_subscription("https://s.example.com", subscription(&["A", "B"]));
        let transport = TransportUse { plugin: "dns-tunnel".into(), fields: [("domain".into(), "t.example.com".into())].into() };
        store.subscriptions[0].entries[1].transport = Some(transport.clone());

        store.update_subscription(id, subscription(&["B", "C"]));
        let entries = &store.subscriptions[0].entries;
        assert_eq!(entries[0].transport, Some(transport));
        assert_eq!(entries[1].transport, None);

        // Saved with the config; old state without the field loads.
        let json = serde_json::to_string(&store).unwrap();
        assert!(json.contains("dns-tunnel"));
        let old: Entry = serde_json::from_str(r#"{ "id": 1, "profile": { "kind": "psiphon", "name": "P", "server_entry": "ab" } }"#).unwrap();
        assert_eq!(old.transport, None);
    }

    #[test]
    fn removing_selected_entry_clears_selection() {
        let mut store = Store::default();
        let ids = store.add_profiles(subscription(&["A", "B"]).profiles);
        store.selected = Some(ids[0]);

        store.remove_entry(ids[1]);
        assert_eq!(store.selected, Some(ids[0]));
        store.remove_entry(ids[0]);
        assert_eq!(store.selected, None);
    }

    #[test]
    fn old_psiphon_network_becomes_a_config() {
        let old = r#"{ "settings": { "psiphon": { "network": { "PropagationChannelId": "A", "SponsorId": "B" }, "region": "DE" } },
                       "selected": 0, "next_id": 4 }"#;
        let store = serde_json::from_str::<Store>(old).unwrap().migrated(old);
        let entry = &store.manual[0];
        assert_eq!(entry.id, 5);
        assert_eq!(store.selected, None);
        let Profile::Psiphon { source: PsiphonSource::Network(network), .. } = &entry.profile else { panic!() };
        assert_eq!(network["SponsorId"], "B");
        assert!(!serde_json::to_string(&store).unwrap().contains("region"));

        let current = serde_json::to_string(&store).unwrap();
        assert_eq!(serde_json::from_str::<Store>(&current).unwrap().migrated(&current).manual.len(), 1);
    }

    #[test]
    fn state_round_trips_through_json() {
        let mut store = Store::default();
        store.add_profiles(subscription(&["A"]).profiles);
        store.add_subscription("https://s.example.com", subscription(&["B"]));

        let loaded: Store = serde_json::from_str(&serde_json::to_string(&store).unwrap()).unwrap();
        assert_eq!(loaded.manual.len(), 1);
        assert_eq!(loaded.subscriptions[0].entries[0].profile.name(), "B");

        // New ids keep counting after a reload.
        let mut loaded = loaded;
        let ids = loaded.add_profiles(subscription(&["C"]).profiles);
        assert_eq!(ids, [4]);
    }
}
