//! Calls into the Java side (android/java: MainActivity, CipherVpnService) for what only Android's
//! Java API can do: the VPN consent dialog and building the TUN with `VpnService.Builder`.

use jni::{JValue, JavaVM, jni_sig, jni_str, objects::{JObject, JString}};
use crate::engine::openvpn::management::TunSpec;
use slint::android::AndroidApp;
use std::sync::OnceLock;

static APP: OnceLock<AndroidApp> = OnceLock::new();

/// Called once from `android_main`.
pub fn init(app: &AndroidApp) {
    let _ = APP.set(app.clone());
}

/// Runs `f` with the activity object on this thread (attached to the VM if needed).
fn with_activity<T>(f: impl FnOnce(&mut jni::Env, &JObject) -> jni::errors::Result<T>) -> Result<T, String> {
    let app = APP.get().ok_or("the Android activity isn't set up")?;
    let vm = JavaVM::singleton().map_err(|e| e.to_string())?;
    vm.attach_current_thread(|env| {
        // A global reference owned by android-activity, valid while the app runs.
        let activity = unsafe { JObject::from_raw(env, app.activity_as_ptr().cast()) };
        f(env, &activity)
    })
    .map_err(|e: jni::errors::Error| format!("Java call failed: {e}"))
}

/// Calls an `int name()` method of the activity.
macro_rules! call_int {
    ($name:literal) => {
        with_activity(|env, activity| env.call_method(activity, jni_str!($name), jni_sig!("()I"), &[])?.i())
    };
}

/// Consent, as the user answered Android's "connection request" dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    Granted,
    Waiting,
    Refused,
}

impl Consent {
    fn from_code(code: i32) -> Self {
        match code {
            1 => Consent::Granted,
            0 => Consent::Waiting,
            _ => Consent::Refused,
        }
    }
}

/// Asks for VPN permission; shows the system dialog the first time (then poll [`consent`]).
/// Also starts `CipherVpnService`, which [`establish`] needs.
pub fn prepare() -> Result<Consent, String> {
    call_int!("vpnPrepare").map(Consent::from_code)
}

pub fn consent() -> Result<Consent, String> {
    call_int!("vpnConsent").map(Consent::from_code)
}

/// Shown when the user said no in Android's VPN dialog.
pub const CONSENT_REFUSED: &str = "Tunnel mode needs the VPN permission: allow it when Android asks.";

/// Updates `consent` while the user decides; an error once they refused.
pub fn check_consent(consent: &mut Consent) -> Result<(), String> {
    if *consent == Consent::Waiting {
        *consent = self::consent()?;
    }
    match consent {
        Consent::Refused => Err(CONSENT_REFUSED.into()),
        _ => Ok(()),
    }
}

/// Builds the TUN. `Ok(None)` while the service is still starting; the fd stays owned by Java
/// (closed by [`stop`]).
pub fn establish(spec: &TunSpec) -> Result<Option<i32>, String> {
    let fd = with_activity(|env, activity| {
        let text = env.new_string(spec.to_lines())?;
        env.call_method(activity, jni_str!("vpnEstablish"), jni_sig!("(Ljava/lang/String;)I"), &[JValue::Object(&text)])?
            .i()
    })?;
    match fd {
        -2 => Ok(None),
        fd if fd < 0 => Err(last_error()),
        fd => Ok(Some(fd)),
    }
}

fn last_error() -> String {
    with_activity(|env, activity| {
        let text = env.call_method(activity, jni_str!("vpnError"), jni_sig!("()Ljava/lang/String;"), &[])?.l()?;
        env.cast_local::<JString>(text)?.try_to_string(env)
    })
    .unwrap_or_else(|e| e)
}

/// Whether Android took the VPN away (another VPN app, or turned off in system settings).
pub fn revoked() -> bool {
    call_int!("vpnRevoked").is_ok_and(|r| r == 1)
}

/// Closes the TUN and stops the service.
pub fn stop() {
    let _ = call_int!("vpnStop");
}
