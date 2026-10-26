//! The Plugins tab, the add-plugin review, plugin settings dialogs, and the transport picker
//! for the selected config.

use super::{Ctx, add_manual, connect, notify, on_ui, refresh_configs, save};
use crate::engine::paths;
use crate::plugin::{self, CoreFormat, FieldKind, Installed, Kind, Manifest, TransportUse, install};
use crate::engine::xray::Core;
use crate::profile::Profile;
use crate::store::{Entry, Store};
use crate::{AppState, AppWindow, ConnectionState, EngineData, FieldData, PluginData};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::{collections::BTreeMap, thread};

/// What the plugin fields dialog is editing.
pub(super) enum FieldsTarget {
    /// The transport of a config (entry id).
    Transport { entry: u64, plugin: String },
    /// A new config for an engine plugin.
    NewConfig { plugin: String },
    /// An engine plugin's config made from its fields (entry id).
    EditConfig { entry: u64, plugin: String },
}

pub(super) fn bind(ui: &AppWindow, ctx: &Ctx) {
    on!(ui, ctx, on_review_plugin, |ui, ctx, source: SharedString| review_plugin(&ui, ctx, &source));
    on!(ui, ctx, on_add_official_plugin, |ui, ctx, id: SharedString| add_official(&ui, ctx, &id));
    on!(ui, ctx, on_pick_plugin_file, |ui, ctx| pick_plugin_file(&ui, ctx));
    on!(ui, ctx, on_install_plugin, |ui, ctx| install_plugin(&ui, ctx));
    on!(ui, ctx, on_remove_plugin, |ui, ctx, id: SharedString| remove_plugin(&ui, ctx, &id));
    on!(ui, ctx, on_allow_plugin_root, |ui, ctx, id: SharedString| allow_root(&ui, ctx, &id));
    on!(ui, ctx, on_revoke_plugin_root, |ui, ctx, id: SharedString| set_root_allowed(&ui, ctx, &id, false));
    on!(ui, ctx, on_new_plugin_config, |ui, ctx, id: SharedString| new_config(&ui, ctx, &id));
    on!(ui, ctx, on_edit_field, |ui, _ctx, index: i32, value: SharedString| {
        let fields = ui.global::<AppState>().get_fields_dialog_fields();
        if let Some(mut field) = fields.row_data(index as usize) {
            field.value = value;
            fields.set_row_data(index as usize, field);
        }
    });
    on!(ui, ctx, on_save_fields, |ui, ctx| save_fields(&ui, ctx));
    on!(ui, ctx, on_cancel_fields, |ui, ctx| {
        ui.global::<AppState>().set_fields_dialog_open(false);
        *ctx.fields_target.lock().unwrap() = None;
        // The transport picker may show a choice that wasn't saved.
        refresh_configs(&ui, ctx);
    });
    on!(ui, ctx, on_transport_changed, |ui, ctx| transport_changed(&ui, ctx));
    on!(ui, ctx, on_edit_transport, |ui, ctx| edit_transport(&ui, ctx));
    on!(ui, ctx, on_edit_plugin_config, |ui, ctx| edit_plugin_config(&ui, ctx));
}

fn installed() -> Vec<Installed> {
    paths::data_dir().map(|dir| plugin::installed(&dir)).unwrap_or_default()
}

fn plugin_data(manifest: &Manifest, official: bool, development: bool, root_allowed: bool) -> PluginData {
    PluginData {
        available: false,
        update: false,
        id: manifest.id.as_str().into(),
        name: manifest.name.as_str().into(),
        kind: match manifest.core {
            Some(_) => "Core",
            None => install::kind_label(manifest.kind),
        }
        .into(),
        version: manifest.version.as_str().into(),
        license: manifest.license.as_str().into(),
        repository: manifest.repository.as_str().into(),
        description: manifest.description.as_str().into(),
        root: manifest.needs_root,
        root_allowed,
        official,
        development,
    }
}

/// Re-reads the installed plugins: the list (then the official plugins not added yet), the link
/// schemes they claim, and the transport picker.
pub(super) fn refresh_plugins(ui: &AppWindow, ctx: &Ctx) {
    let plugins = installed();
    plugin::register_schemes(&plugins);
    let rows = plugin_rows(&plugins, &plugin::official());
    let state = ui.global::<AppState>();
    state.set_plugins(ModelRc::new(VecModel::from(rows)));
    state.set_plugin_dev_mode(install::dev_mode());
    let core = ctx.store.lock().unwrap().settings.core.clone();
    refresh_cores(&state, &core);
    refresh_configs(ui, ctx);
}

/// Settings → Core: the built-in engines, then the installed core plugins. A core plugin that
/// was removed stays listed as such, so the setting doesn't silently change.
pub(super) fn core_choices(current: &Core) -> Vec<(Core, String)> {
    let mut choices = vec![(Core::SingBox, "sing-box".to_owned()), (Core::Xray, "Xray".to_owned())];
    let cores = installed().into_iter().filter(|p| p.manifest.core.is_some());
    choices.extend(cores.map(|p| (Core::Plugin(p.manifest.id), p.manifest.name)));
    if let Core::Plugin(id) = current
        && !choices.iter().any(|(core, _)| core == current)
    {
        choices.push((current.clone(), format!("{id} (not installed)")));
    }
    choices
}

pub(super) fn refresh_cores(state: &AppState, current: &Core) {
    let engines: Vec<EngineData> = installed()
        .iter()
        .filter_map(|p| Some((p, p.manifest.core.as_ref()?)))
        .map(|(p, core)| {
            let format = match core.format {
                CoreFormat::SingBox => "sing-box",
                CoreFormat::Xray => "Xray",
            };
            let mut status = format!("v{} · plugin, runs {format} configs", p.manifest.version);
            if !core.protocols.is_empty() {
                status += &format!(" and {}", core.protocols.join(", "));
            }
            if !p.usable() {
                status += " · needs administrator rights: allow them in Plugins";
            }
            EngineData { name: p.manifest.name.as_str().into(), status: status.into() }
        })
        .collect();
    state.set_core_plugins(ModelRc::new(VecModel::from(engines)));
    let choices = core_choices(current);
    let names: Vec<SharedString> = choices.iter().map(|(_, name)| name.as_str().into()).collect();
    state.set_cores(ModelRc::new(VecModel::from(names)));
    state.set_core(choices.iter().position(|(core, _)| core == current).unwrap_or(0) as i32);
}

/// Installed plugins (an official one whose built-in manifest is newer can be updated), then
/// the official plugins that aren't installed.
fn plugin_rows(plugins: &[Installed], official: &[Manifest]) -> Vec<PluginData> {
    let mut rows: Vec<PluginData> = plugins
        .iter()
        .map(|p| PluginData {
            update: p.record.official && official.iter().any(|m| m.id == p.manifest.id && *m != p.manifest),
            ..plugin_data(&p.manifest, p.record.official, p.record.development, p.record.root_allowed)
        })
        .collect();
    let available = official.iter().filter(|m| !plugins.iter().any(|p| p.manifest.id == m.id));
    rows.extend(available.map(|m| PluginData { available: true, ..plugin_data(m, true, false, false) }));
    rows
}

/// The transport picker for the selected config: whether it applies, the choices ("None" first)
/// and the current one.
pub(super) fn refresh_transport(state: &AppState, store: &Store) {
    let entry = store.selected.and_then(|id| store.entry(id));
    let available = entry.is_some_and(|e| matches!(e.profile, Profile::Proxy { .. } | Profile::Xray { .. }));
    let transports = transports();
    let current = entry.and_then(|e| e.transport.as_ref());
    let index = current.and_then(|t| transports.iter().position(|p| p.manifest.id == t.plugin)).map_or(0, |i| i + 1);
    let has_fields = current.and_then(|t| transports.iter().find(|p| p.manifest.id == t.plugin)).is_some_and(|p| !p.manifest.fields.is_empty());

    let mut names = vec![SharedString::from("None")];
    names.extend(transports.iter().map(|p| SharedString::from(p.manifest.name.as_str())));
    // A config whose transport plugin was removed: say so instead of silently showing "None".
    if let Some(missing) = current.filter(|_| index == 0) {
        names.push(format!("{} (not installed)", missing.plugin).into());
    }
    let index = if current.is_some() && index == 0 { names.len() - 1 } else { index };
    // An engine plugin's config made from its fields can be edited.
    let editable = match entry.map(|e| &e.profile) {
        Some(Profile::Plugin { plugin, link: None, .. }) => installed().iter().any(|p| p.manifest.id == *plugin && !p.manifest.fields.is_empty()),
        _ => false,
    };
    state.set_plugin_config_editable(editable);
    state.set_transport_available(available);
    state.set_transports(ModelRc::new(VecModel::from(names)));
    state.set_selected_transport(index as i32);
    state.set_transport_has_fields(has_fields);
}

fn transports() -> Vec<Installed> {
    installed().into_iter().filter(|p| p.manifest.kind == Kind::Transport).collect()
}

// ───────────────────────────── Adding plugins ─────────────────────────────

/// Step 1 → 2 of the add dialog: fetch and check the plugin. An empty source goes back to step 1.
fn review_plugin(ui: &AppWindow, ctx: &Ctx, source: &str) {
    if source.trim().is_empty() {
        let state = ui.global::<AppState>();
        state.set_plugin_dialog_error(SharedString::new());
        state.set_plugin_review_ready(false);
        *ctx.plugin_review.lock().unwrap() = None;
        return;
    }
    let source = source.to_owned();
    review_with(ui, ctx, move || install::review(&source));
}

/// An official plugin from the list ("Add" or "Update"): straight to the review step.
fn add_official(ui: &AppWindow, ctx: &Ctx, id: &str) {
    let state = ui.global::<AppState>();
    state.set_plugin_dialog_source(SharedString::new());
    state.set_plugin_dialog_open(true);
    let id = id.to_owned();
    review_with(ui, ctx, move || install::review_official(&id));
}

fn review_with(ui: &AppWindow, ctx: &Ctx, review: impl FnOnce() -> Result<install::Review, String> + Send + 'static) {
    let state = ui.global::<AppState>();
    state.set_plugin_dialog_error(SharedString::new());
    state.set_plugin_review_ready(false);
    *ctx.plugin_review.lock().unwrap() = None;
    state.set_plugin_dialog_busy(true);
    let weak = ui.as_weak();
    let ctx2 = ctx.clone();
    thread::spawn(move || {
        let result = review();
        on_ui(&weak, &ctx2, move |ui, ctx| {
            let state = ui.global::<AppState>();
            state.set_plugin_dialog_busy(false);
            match result {
                Ok(review) => {
                    let manifest = &review.manifest;
                    state.set_plugin_review(plugin_data(manifest, review.official, review.development, false));
                    let warnings: Vec<SharedString> = review.warnings.iter().map(|w| w.as_str().into()).collect();
                    state.set_plugin_review_warnings(ModelRc::new(VecModel::from(warnings)));
                    state.set_plugin_review_allow_root(false);
                    state.set_plugin_review_ready(true);
                    *ctx.plugin_review.lock().unwrap() = Some(review);
                }
                Err(e) => state.set_plugin_dialog_error(e.into()),
            }
        });
    });
}

fn pick_plugin_file(ui: &AppWindow, ctx: &Ctx) {
    let weak = ui.as_weak();
    let ctx = ctx.clone();
    thread::spawn(move || {
        let Some(file) = rfd::FileDialog::new()
            .set_title("Pick a plugin manifest")
            .add_filter("Plugin manifest", &["json"])
            .pick_file()
        else {
            return;
        };
        on_ui(&weak, &ctx, move |ui, ctx| {
            let source = file.display().to_string();
            ui.global::<AppState>().set_plugin_dialog_source(source.as_str().into());
            review_plugin(ui, ctx, &source);
        });
    });
}

fn install_plugin(ui: &AppWindow, ctx: &Ctx) {
    let Some(review) = ctx.plugin_review.lock().unwrap().clone() else { return };
    let state = ui.global::<AppState>();
    let allow_root = state.get_plugin_review_allow_root();
    state.set_plugin_dialog_busy(true);
    state.set_plugin_dialog_error(SharedString::new());

    let weak = ui.as_weak();
    let ctx = ctx.clone();
    thread::spawn(move || {
        let result = paths::data_dir().map_err(|e| e.to_string()).and_then(|dir| install::install(&dir, &review, allow_root));
        on_ui(&weak, &ctx, move |ui, ctx| {
            let state = ui.global::<AppState>();
            state.set_plugin_dialog_busy(false);
            match result {
                Ok(plugin) => {
                    state.set_plugin_dialog_open(false);
                    state.set_plugin_review_ready(false);
                    state.set_plugin_dialog_source(SharedString::new());
                    *ctx.plugin_review.lock().unwrap() = None;
                    refresh_plugins(ui, ctx);
                    let note = match plugin.usable() {
                        true => "",
                        false => ": allow its administrator rights in Plugins to use it",
                    };
                    notify(ui, ctx, format!("Added {} {}{note}", plugin.manifest.name, plugin.manifest.version), false);
                }
                Err(e) => state.set_plugin_dialog_error(e.into()),
            }
        });
    });
}

fn remove_plugin(ui: &AppWindow, ctx: &Ctx, id: &str) {
    let result = paths::data_dir().map_err(|e| e.to_string()).and_then(|dir| install::remove(&dir, id));
    match result {
        Ok(()) => {
            refresh_plugins(ui, ctx);
            notify(ui, ctx, "Plugin removed. Configs that used it stay, but won't connect until it's back.", false);
        }
        Err(e) => notify(ui, ctx, format!("Couldn't remove the plugin: {e}"), true),
    }
}

/// From the plugin list: ask first. From that dialog (same id): allow.
fn allow_root(ui: &AppWindow, ctx: &Ctx, id: &str) {
    let state = ui.global::<AppState>();
    if state.get_plugin_root_dialog_id() == id {
        state.set_plugin_root_dialog_id(SharedString::new());
        set_root_allowed(ui, ctx, id, true);
        return;
    }
    let name = installed().into_iter().find(|p| p.manifest.id == id).map(|p| p.manifest.name).unwrap_or_default();
    state.set_plugin_root_dialog_name(name.into());
    state.set_plugin_root_dialog_id(id.into());
}

fn set_root_allowed(ui: &AppWindow, ctx: &Ctx, id: &str, allowed: bool) {
    let result = paths::data_dir().map_err(|e| e.to_string()).and_then(|dir| {
        let mut plugin = plugin::load(&dir, id)?;
        plugin.record.root_allowed = allowed && plugin.manifest.needs_root;
        plugin::save_record(&dir, id, &plugin.record).map_err(|e| e.to_string())
    });
    if let Err(e) = result {
        notify(ui, ctx, format!("Couldn't change the plugin: {e}"), true);
    }
    refresh_plugins(ui, ctx);
}

// ───────────────────────────── Plugin settings ─────────────────────────────

/// `name`: ask for the config's name too, starting with this one.
fn open_fields(ui: &AppWindow, ctx: &Ctx, title: String, name: Option<&str>, manifest: &Manifest, values: &BTreeMap<String, String>, target: FieldsTarget) {
    let fields: Vec<FieldData> = manifest
        .fields
        .iter()
        .map(|field| FieldData {
            key: field.key.as_str().into(),
            label: field.label.as_str().into(),
            kind: match field.kind {
                FieldKind::Text => "text",
                FieldKind::Number => "number",
                FieldKind::Bool => "bool",
                FieldKind::Select => "select",
                FieldKind::Lines => "lines",
            }
            .into(),
            hint: field.hint.as_str().into(),
            required: field.required,
            value: values.get(&field.key).unwrap_or(&field.default).as_str().into(),
            options: ModelRc::new(VecModel::from(field.options.iter().map(|o| SharedString::from(o.as_str())).collect::<Vec<_>>())),
        })
        .collect();
    let state = ui.global::<AppState>();
    state.set_fields_dialog_title(title.into());
    state.set_fields_dialog_needs_name(name.is_some());
    state.set_fields_dialog_name(name.unwrap_or_default().into());
    state.set_fields_dialog_fields(ModelRc::new(VecModel::from(fields)));
    state.set_fields_dialog_error(SharedString::new());
    state.set_fields_dialog_open(true);
    *ctx.fields_target.lock().unwrap() = Some(target);
}

fn load_plugin(ui: &AppWindow, ctx: &Ctx, id: &str) -> Option<Installed> {
    match paths::data_dir().map_err(|e| e.to_string()).and_then(|dir| plugin::load(&dir, id)) {
        Ok(plugin) => Some(plugin),
        Err(e) => {
            notify(ui, ctx, e, true);
            None
        }
    }
}

fn new_config(ui: &AppWindow, ctx: &Ctx, id: &str) {
    let Some(plugin) = load_plugin(ui, ctx, id) else { return };
    let title = format!("New {} config", plugin.manifest.name);
    open_fields(ui, ctx, title, Some(""), &plugin.manifest, &BTreeMap::new(), FieldsTarget::NewConfig { plugin: id.into() });
}

fn edit_plugin_config(ui: &AppWindow, ctx: &Ctx) {
    let Some(entry) = selected_entry(ctx) else { return };
    let Profile::Plugin { name, plugin: id, link: None, fields } = &entry.profile else { return };
    let Some(plugin) = load_plugin(ui, ctx, id) else { return };
    let target = FieldsTarget::EditConfig { entry: entry.id, plugin: id.clone() };
    open_fields(ui, ctx, format!("{name} settings"), Some(name), &plugin.manifest, fields, target);
}

fn save_fields(ui: &AppWindow, ctx: &Ctx) {
    let state = ui.global::<AppState>();
    let Some(target) = ctx.fields_target.lock().unwrap().take() else { return };
    let values: BTreeMap<String, String> =
        state.get_fields_dialog_fields().iter().map(|f| (f.key.to_string(), f.value.to_string())).collect();
    let id = match &target {
        FieldsTarget::Transport { plugin, .. } | FieldsTarget::NewConfig { plugin } | FieldsTarget::EditConfig { plugin, .. } => plugin.clone(),
    };
    let checked = load_plugin(ui, ctx, &id).ok_or_else(String::new).and_then(|p| p.manifest.fill_fields(&values));
    let fields = match checked {
        Ok(fields) => fields,
        Err(e) => {
            state.set_fields_dialog_error(e.into());
            *ctx.fields_target.lock().unwrap() = Some(target);
            return;
        }
    };

    let name = state.get_fields_dialog_name().trim().to_owned();
    if name.is_empty() && !matches!(target, FieldsTarget::Transport { .. }) {
        state.set_fields_dialog_error("Give the config a name".into());
        *ctx.fields_target.lock().unwrap() = Some(target);
        return;
    }
    match target {
        FieldsTarget::NewConfig { plugin } => {
            state.set_fields_dialog_open(false);
            let ids = add_manual(ui, ctx, vec![Profile::Plugin { name, plugin, link: None, fields }]);
            if let Some(id) = ids.first() {
                super::select_config(ui, ctx, *id);
            }
            state.set_current_tab(1);
        }
        FieldsTarget::Transport { entry, plugin } => {
            state.set_fields_dialog_open(false);
            set_transport(ui, ctx, entry, Some(TransportUse { plugin, fields }));
        }
        FieldsTarget::EditConfig { entry, plugin } => {
            state.set_fields_dialog_open(false);
            set_profile(ui, ctx, entry, Profile::Plugin { name, plugin, link: None, fields });
        }
    }
}

/// Replaces a config's profile; a live connection with it reconnects.
fn set_profile(ui: &AppWindow, ctx: &Ctx, id: u64, profile: Profile) {
    let selected = {
        let mut store = ctx.store.lock().unwrap();
        let Some(entry) = store.entry_mut(id) else { return };
        entry.profile = profile;
        save(ui, ctx, &store);
        store.selected == Some(id)
    };
    refresh_configs(ui, ctx);
    if selected && *ctx.state.lock().unwrap() == ConnectionState::Connected {
        connect(ui, ctx);
    }
}

// ───────────────────────────── Transport picker ─────────────────────────────

fn selected_entry(ctx: &Ctx) -> Option<Entry> {
    let store = ctx.store.lock().unwrap();
    store.selected.and_then(|id| store.entry(id)).cloned()
}

fn transport_changed(ui: &AppWindow, ctx: &Ctx) {
    let Some(entry) = selected_entry(ctx) else { return };
    let index = ui.global::<AppState>().get_selected_transport();
    let transports = transports();
    let Some(plugin) = (index > 0).then(|| transports.get(index as usize - 1)).flatten() else {
        // "None" (or the entry for a removed plugin).
        if index == 0 {
            set_transport(ui, ctx, entry.id, None);
        }
        return;
    };
    let manifest = &plugin.manifest;
    // Keep the values when the same plugin is picked again.
    let values = entry.transport.filter(|t| t.plugin == manifest.id).map(|t| t.fields).unwrap_or_default();
    match manifest.fill_fields(&values) {
        // Nothing to ask (or everything has defaults): use it right away.
        Ok(fields) if manifest.fields.iter().all(|f| !f.required || values.contains_key(&f.key)) => {
            set_transport(ui, ctx, entry.id, Some(TransportUse { plugin: manifest.id.clone(), fields }));
        }
        _ => {
            let target = FieldsTarget::Transport { entry: entry.id, plugin: manifest.id.clone() };
            open_fields(ui, ctx, format!("{} settings", manifest.name), None, manifest, &values, target);
        }
    }
}

fn edit_transport(ui: &AppWindow, ctx: &Ctx) {
    let Some(entry) = selected_entry(ctx) else { return };
    let Some(transport) = entry.transport else { return };
    let Some(plugin) = load_plugin(ui, ctx, &transport.plugin) else { return };
    let target = FieldsTarget::Transport { entry: entry.id, plugin: transport.plugin.clone() };
    open_fields(ui, ctx, format!("{} settings", plugin.manifest.name), None, &plugin.manifest, &transport.fields, target);
}

fn set_transport(ui: &AppWindow, ctx: &Ctx, id: u64, transport: Option<TransportUse>) {
    {
        let mut store = ctx.store.lock().unwrap();
        let Some(entry) = store.entry_mut(id) else { return };
        if entry.transport == transport {
            return;
        }
        entry.transport = transport;
        save(ui, ctx, &store);
    }
    refresh_configs(ui, ctx);
    // Like switching configs: a live connection moves over.
    if *ctx.state.lock().unwrap() == ConnectionState::Connected {
        connect(ui, ctx);
    }
}

#[cfg(test)]
pub(super) fn plugin_data_for_tests(manifest: &Manifest) -> PluginData {
    plugin_data(manifest, false, false, false)
}
