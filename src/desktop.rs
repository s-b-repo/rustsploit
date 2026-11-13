// src/desktop.rs
//
// Desktop-environment integration: KDE Plasma / GNOME and friends.
//
// Two independent channels, both of which work the same way on Plasma and on
// GNOME, and both of which degrade to a no-op when the environment is not
// available:
//
//   1. FREEDESKTOP NOTIFICATIONS over the session bus
//      (`org.freedesktop.Notifications`). Plasma's `plasma-notification`
//      service and GNOME's `gnome-shell` both own this name, so the same
//      call reaches either. This is the "proper" integration: it goes
//      through D-Bus, not through shelling out to `notify-send`, so it
//      respects the user's notification settings and works under Wayland.
//
//   2. TERMINAL TITLE via an OSC escape sequence. Konsole and GNOME Terminal
//      (VTE) both honour OSC 0/2, so the operator can see the scan's state
//      from the taskbar entry without switching back to the terminal.
//
// Neither channel is allowed to break a scan: every call here reports
// failure through a `Result` and the callers log and continue.

use std::fmt;

/// The freedesktop notification service. Both Plasma and GNOME implement it.
const NOTIFY_BUS_NAME: &str = "org.freedesktop.Notifications";
const NOTIFY_OBJECT_PATH: &str = "/org/freedesktop/Notifications";
const NOTIFY_INTERFACE: &str = "org.freedesktop.Notifications";

/// The desktop environment the shell is running under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopEnvironment {
    /// KDE Plasma (Wayland or X11).
    Plasma,
    /// GNOME (and GNOME Shell / Mutter based sessions).
    Gnome,
    /// Any other freedesktop session (wlroots, Sway, XFCE, Cinnamon, ...).
    Other,
    /// Not a graphical session, or the environment could not be identified.
    Unknown,
}

impl DesktopEnvironment {
    /// A short human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            DesktopEnvironment::Plasma => "KDE Plasma",
            DesktopEnvironment::Gnome => "GNOME",
            DesktopEnvironment::Other => "other desktop",
            DesktopEnvironment::Unknown => "unknown / headless",
        }
    }

    /// Is this a session the framework knows how to talk to?
    pub fn is_known(&self) -> bool {
        matches!(self, DesktopEnvironment::Plasma | DesktopEnvironment::Gnome)
    }
}

impl fmt::Display for DesktopEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Detect the running desktop environment.
///
/// `XDG_CURRENT_DESKTOP` is the authoritative variable; it holds a
/// colon-separated list (`"KDE"` on Plasma, `"GNOME"` on GNOME, and
/// `"ubuntu:GNOME"` on Ubuntu). `DESKTOP_SESSION` is the older fallback, and
/// `XDG_SESSION_TYPE` distinguishes a graphical session from a TTY.
pub fn detect() -> DesktopEnvironment {
    let current = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    let session = std::env::var("DESKTOP_SESSION").unwrap_or_default();
    let session_type = std::env::var("XDG_SESSION_TYPE").unwrap_or_default();

    // A TTY / SSH session has no desktop at all.
    if session_type == "tty" || (current.is_empty() && session.is_empty()) {
        return DesktopEnvironment::Unknown;
    }

    let haystack = format!("{current}:{session}").to_ascii_lowercase();
    // "kde" matches "KDE" and "KDE Plasma"; "plasma" covers the standalone
    // Plasma Shell session.
    if haystack.contains("kde") || haystack.contains("plasma") {
        return DesktopEnvironment::Plasma;
    }
    // "gnome" matches "GNOME" and "ubuntu:GNOME"; "unity" and "cinnamon" are
    // GTK shells and speak the same notification protocol.
    if haystack.contains("gnome")
        || haystack.contains("unity")
        || haystack.contains("cinnamon")
        || haystack.contains("mate")
        || haystack.contains("budgie")
        || haystack.contains("xfce")
    {
        return DesktopEnvironment::Gnome;
    }
    if !haystack.trim_matches(':').is_empty() {
        return DesktopEnvironment::Other;
    }
    DesktopEnvironment::Unknown
}

/// Notification urgency, mapping to the freedesktop urgency levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Urgency {
    Low,
    Normal,
    Critical,
}

impl Urgency {
    /// The freedesktop urgency is a `u32` on the wire.
    fn as_u32(self) -> u32 {
        match self {
            Urgency::Low => 0,
            Urgency::Normal => 1,
            Urgency::Critical => 2,
        }
    }
}

/// Is a notification daemon reachable on the session bus?
///
/// Cheap check: look up the well-known name's owner. On a headless box there
/// is no session bus at all, and the lookup fails immediately.
#[cfg(feature = "desktop")]
pub async fn notifications_available() -> bool {
    if std::env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
        return false;
    }
    let Ok(conn) = zbus::Connection::session().await else {
        return false;
    };
    matches!(
        zbus::Proxy::new(
            &conn,
            NOTIFY_BUS_NAME,
            NOTIFY_OBJECT_PATH,
            NOTIFY_INTERFACE
        )
        .await,
        Ok(_)
    )
}

/// Without the `desktop` feature there is no session-bus client, so no
/// notification daemon can be reached.
#[cfg(not(feature = "desktop"))]
pub async fn notifications_available() -> bool {
    false
}

/// Send a desktop notification.
///
/// Works identically under KDE Plasma and GNOME because both implement
/// `org.freedesktop.Notifications`. Errors are returned, never swallowed —
/// the caller decides whether a missing notification daemon matters.
#[cfg(feature = "desktop")]
pub async fn notify(title: &str, body: &str, urgency: Urgency) -> anyhow::Result<()> {
    let conn = zbus::Connection::session()
        .await
        .map_err(|e| anyhow::anyhow!("session bus unavailable: {e}"))?;
    let proxy = zbus::Proxy::new(
        &conn,
        NOTIFY_BUS_NAME,
        NOTIFY_OBJECT_PATH,
        NOTIFY_INTERFACE,
    )
    .await
    .map_err(|e| anyhow::anyhow!("notification service unavailable: {e}"))?;

    // Owned Strings throughout: a tuple of `&str` borrows the session bus
    // lifetime and does not satisfy the D-Bus body type.
    let notification = (
        "rustsploit".to_string(), // app_name
        0u32,                    // replaces_id
        "rustsploit".to_string(), // app_icon
        title.to_string(),        // summary
        body.to_string(),         // body
        vec![String::new()],      // actions
        urgency.as_u32(),         // urgency
        0i32,                     // expire_timeout (0 = server default)
    );
    // `Proxy::call` is generic over the reply type; `Notify` returns the
    // notification id (a u32). Without the annotation Rust cannot infer it.
    let reply: u32 = proxy
        .call("Notify", &notification)
        .await
        .map_err(|e| anyhow::anyhow!("notification failed: {e}"))?;
    tracing::debug!("desktop notification id {reply}");
    Ok(())
}

/// Without the `desktop` feature notifications are unavailable. The error
/// says why, so the caller can tell the operator rather than silently
/// dropping the message.
#[cfg(not(feature = "desktop"))]
pub async fn notify(_title: &str, _body: &str, _urgency: Urgency) -> anyhow::Result<()> {
    anyhow::bail!("desktop notifications require the `desktop` feature")
}

/// Set the terminal window/tab title.
///
/// Uses OSC 2, which Konsole and GNOME Terminal both honour. A terminal that
/// does not understand the sequence ignores it — the escape is written to
/// stdout, so it must not be captured into the spool or the results file.
///
/// The caller is responsible for writing to the real stdout.
pub fn terminal_title(title: &str) -> String {
    // Strip any control characters: the title is echoed by the terminal and
    // must not be able to inject escape sequences of its own.
    let clean: String = title
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect();
    format!("\x1b]2;{clean}\x07")
}

/// Report the desktop environment and the notification capability.
///
/// Used by the `desktop` shell command.
pub async fn describe() -> String {
    let de = detect();
    let mut out = String::new();
    out.push_str(&format!("Desktop environment : {de}\n"));
    out.push_str(&format!(
        "XDG_CURRENT_DESKTOP   : {}\n",
        std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_else(|_| "(unset)".into())
    ));
    out.push_str(&format!(
        "DESKTOP_SESSION       : {}\n",
        std::env::var("DESKTOP_SESSION").unwrap_or_else(|_| "(unset)".into())
    ));
    out.push_str(&format!(
        "XDG_SESSION_TYPE      : {}\n",
        std::env::var("XDG_SESSION_TYPE").unwrap_or_else(|_| "(unset)".into())
    ));
    out.push_str(&format!(
        "Session bus           : {}\n",
        match std::env::var("DBUS_SESSION_BUS_ADDRESS") {
            Ok(v) if !v.is_empty() => "present",
            _ => "absent",
        }
    ));
    out.push_str(&format!(
        "Notifications         : {}",
        if notifications_available().await {
            "available (org.freedesktop.Notifications)"
        } else {
            "unavailable — results are printed to the console only"
        }
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_title_strips_control_characters() {
        // A title carrying an escape sequence must not be able to emit one.
        let title = terminal_title("scan\u{1b}[31mred\u{7}");
        assert!(!title.contains('\u{1b}'));
        assert!(title.starts_with("\x1b]2;"));
        assert!(title.ends_with('\x07'));
    }

    #[test]
    fn terminal_title_is_length_bounded() {
        let title = terminal_title(&"x".repeat(500));
        // OSC 2; + 120 chars + BEL
        assert!(title.len() <= 8 + 120 + 1);
    }

    #[test]
    fn desktop_environments_are_labelled() {
        assert_eq!(DesktopEnvironment::Plasma.label(), "KDE Plasma");
        assert_eq!(DesktopEnvironment::Gnome.label(), "GNOME");
        assert!(DesktopEnvironment::Plasma.is_known());
        assert!(!DesktopEnvironment::Unknown.is_known());
    }
}
