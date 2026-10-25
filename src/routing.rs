//! Routing rules and split tunneling: which traffic skips the tunnel, uses it, or is blocked.
//! The sing-box config for them is built in `engine::singbox::generate::routing`.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Where matching traffic goes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    #[default]
    Proxy,
    Direct,
    Block,
}

/// What a rule matches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    /// A domain and its subdomains.
    Domain,
    /// Domains containing a word.
    Keyword,
    /// IP address or CIDR.
    Ip,
    /// Destination port or `from:to` range.
    Port,
    /// Process name (`firefox`, `chrome.exe`) or full path.
    App,
    /// A geosite list, e.g. `category-ir`.
    Geosite,
    /// A geoip list, e.g. `ir`.
    Geoip,
}

impl RuleKind {
    /// Same order as the kind picker in the UI.
    pub const ALL: [RuleKind; 7] =
        [RuleKind::Domain, RuleKind::Keyword, RuleKind::Ip, RuleKind::Port, RuleKind::App, RuleKind::Geosite, RuleKind::Geoip];

    pub fn label(self) -> &'static str {
        match self {
            RuleKind::Domain => "Domain",
            RuleKind::Keyword => "Keyword",
            RuleKind::Ip => "IP",
            RuleKind::Port => "Port",
            RuleKind::App => "App",
            RuleKind::Geosite => "Geosite",
            RuleKind::Geoip => "GeoIP",
        }
    }

    /// Whether the rule matches destination IPs (needs a resolved address in the proxy modes).
    pub fn matches_ip(self) -> bool {
        matches!(self, RuleKind::Ip | RuleKind::Geoip)
    }
}

/// One-click geo rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Preset {
    IranDirect,
    ChinaDirect,
    RussiaDirect,
    BlockAds,
}

impl Preset {
    /// Same order as the preset list in the UI.
    pub const ALL: [Preset; 4] = [Preset::IranDirect, Preset::ChinaDirect, Preset::RussiaDirect, Preset::BlockAds];

    pub fn label(self) -> &'static str {
        match self {
            Preset::IranDirect => "Iran direct",
            Preset::ChinaDirect => "China direct",
            Preset::RussiaDirect => "Russia direct",
            Preset::BlockAds => "Block ads",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Preset::IranDirect => "Iranian sites and IPs skip the tunnel.",
            Preset::ChinaDirect => "Chinese sites and IPs skip the tunnel.",
            Preset::RussiaDirect => "Russian sites and IPs skip the tunnel.",
            Preset::BlockAds => "Ad and tracker domains are blocked.",
        }
    }

    /// The rules the preset stands for.
    pub fn rules(self) -> Vec<Rule> {
        let geo = |kind, code: &str, target| Rule { enabled: true, kind, values: vec![code.into()], target };
        match self {
            Preset::IranDirect => vec![
                geo(RuleKind::Geosite, "category-ir", Target::Direct),
                geo(RuleKind::Geoip, "ir", Target::Direct),
            ],
            Preset::ChinaDirect => vec![
                geo(RuleKind::Geosite, "cn", Target::Direct),
                geo(RuleKind::Geoip, "cn", Target::Direct),
            ],
            Preset::RussiaDirect => vec![
                geo(RuleKind::Geosite, "category-ru", Target::Direct),
                geo(RuleKind::Geoip, "ru", Target::Direct),
            ],
            Preset::BlockAds => vec![geo(RuleKind::Geosite, "category-ads-all", Target::Block)],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub enabled: bool,
    pub kind: RuleKind,
    /// Normalized by [`Rule::parse`].
    pub values: Vec<String>,
    pub target: Target,
}

impl Rule {
    /// Splits user input on newlines and commas and normalizes each value.
    pub fn parse(kind: RuleKind, text: &str) -> Result<Vec<String>, String> {
        let mut values = Vec::new();
        for raw in text.split(['\n', ',']).map(str::trim).filter(|v| !v.is_empty()) {
            let value = normalize(kind, raw).ok_or_else(|| format!("\"{raw}\" isn't a valid {}", kind.label().to_lowercase()))?;
            if !values.contains(&value) {
                values.push(value);
            }
        }
        match values.is_empty() {
            true => Err("Enter at least one value.".into()),
            false => Ok(values),
        }
    }

    /// Short text for the rule list: the first values, then "+N".
    pub fn summary(&self) -> String {
        const SHOWN: usize = 2;
        let mut text = self.values.iter().take(SHOWN).cloned().collect::<Vec<_>>().join(", ");
        if self.values.len() > SHOWN {
            text += &format!(" +{}", self.values.len() - SHOWN);
        }
        text
    }
}

fn normalize(kind: RuleKind, value: &str) -> Option<String> {
    match kind {
        RuleKind::Domain => domain(value),
        RuleKind::Keyword => Some(value.to_lowercase()),
        RuleKind::Ip => cidr(value),
        RuleKind::Port => port(value),
        RuleKind::App => Some(value.to_owned()),
        RuleKind::Geosite | RuleKind::Geoip => {
            let code = value.to_lowercase();
            code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-').then_some(code)
        }
    }
}

/// `https://www.Example.com/path` → `www.example.com`; `*.example.com` → `example.com`.
fn domain(value: &str) -> Option<String> {
    let value = value.split_once("://").map_or(value, |(_, rest)| rest);
    let host = value.split(['/', '?', '#']).next()?;
    let host = host.trim_start_matches("*.").trim_start_matches('.').trim_end_matches('.').to_lowercase();
    let valid = !host.is_empty()
        && host.split('.').all(|label| !label.is_empty() && label.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
    valid.then_some(host)
}

/// `1.2.3.4` → `1.2.3.4/32`; prefixes are checked against the address family.
fn cidr(value: &str) -> Option<String> {
    let (addr, prefix) = value.split_once('/').map_or((value, None), |(a, p)| (a, Some(p)));
    let addr: IpAddr = addr.trim_matches(['[', ']']).parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix: u8 = match prefix {
        Some(p) => p.parse().ok().filter(|&p| p <= max)?,
        None => max,
    };
    Some(format!("{addr}/{prefix}"))
}

/// `443` or `1000:2000` (`-` also accepted for ranges).
fn port(value: &str) -> Option<String> {
    let parse = |p: &str| p.trim().parse::<u16>().ok().filter(|&p| p > 0);
    match value.split_once([':', '-']) {
        Some((from, to)) => {
            let (from, to) = (parse(from)?, parse(to)?);
            (from <= to).then(|| format!("{from}:{to}"))
        }
        None => parse(value).map(|p| p.to_string()),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Routing {
    /// Where traffic no rule matches goes. `Direct` makes the rules a whitelist.
    pub default: Target,
    pub presets: Vec<Preset>,
    /// Checked top to bottom before the presets; the first match wins.
    pub rules: Vec<Rule>,
}

impl Routing {
    /// Enabled custom rules first, then the presets' rules (block before direct).
    pub fn effective_rules(&self) -> Vec<Rule> {
        let mut rules: Vec<Rule> = self.rules.iter().filter(|r| r.enabled).cloned().collect();
        let mut presets: Vec<Rule> = Preset::ALL
            .into_iter()
            .filter(|p| self.presets.contains(p))
            .flat_map(Preset::rules)
            .collect();
        presets.sort_by_key(|r| r.target != Target::Block);
        rules.extend(presets);
        rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_domains() {
        assert_eq!(
            Rule::parse(RuleKind::Domain, "https://WWW.Example.com/path?q, *.ir\n.co.uk.\n\n").unwrap(),
            ["www.example.com", "ir", "co.uk"]
        );
        assert!(Rule::parse(RuleKind::Domain, "exa mple.com").is_err());
        assert!(Rule::parse(RuleKind::Domain, "a..b").is_err());
    }

    #[test]
    fn normalizes_ips() {
        assert_eq!(
            Rule::parse(RuleKind::Ip, "1.2.3.4, 10.0.0.0/8\n2001:db8::/32\n[::1]").unwrap(),
            ["1.2.3.4/32", "10.0.0.0/8", "2001:db8::/32", "::1/128"]
        );
        assert!(Rule::parse(RuleKind::Ip, "1.2.3.4/33").is_err());
        assert!(Rule::parse(RuleKind::Ip, "example.com").is_err());
    }

    #[test]
    fn normalizes_ports() {
        assert_eq!(Rule::parse(RuleKind::Port, "443, 1000-2000, 5000:6000").unwrap(), ["443", "1000:2000", "5000:6000"]);
        assert!(Rule::parse(RuleKind::Port, "0").is_err());
        assert!(Rule::parse(RuleKind::Port, "70000").is_err());
        assert!(Rule::parse(RuleKind::Port, "2000:1000").is_err());
    }

    #[test]
    fn apps_geo_and_duplicates() {
        assert_eq!(
            Rule::parse(RuleKind::App, "firefox\n/usr/bin/telegram-desktop\nfirefox").unwrap(),
            ["firefox", "/usr/bin/telegram-desktop"]
        );
        assert_eq!(Rule::parse(RuleKind::Geosite, "Category-IR").unwrap(), ["category-ir"]);
        assert!(Rule::parse(RuleKind::Geoip, "i r").is_err());
        assert!(Rule::parse(RuleKind::Geoip, " , ").is_err());
    }

    #[test]
    fn summary_shortens_long_lists() {
        let rule = Rule { enabled: true, kind: RuleKind::Domain, values: vec!["a.com".into(), "b.com".into(), "c.com".into()], target: Target::Direct };
        assert_eq!(rule.summary(), "a.com, b.com +1");
    }

    #[test]
    fn custom_rules_come_before_presets_and_blocks_before_direct() {
        let routing = Routing {
            default: Target::Proxy,
            presets: vec![Preset::IranDirect, Preset::BlockAds],
            rules: vec![
                Rule { enabled: false, kind: RuleKind::Port, values: vec!["25".into()], target: Target::Block },
                Rule { enabled: true, kind: RuleKind::App, values: vec!["firefox".into()], target: Target::Direct },
            ],
        };
        let rules = routing.effective_rules();
        let kinds: Vec<_> = rules.iter().map(|r| (r.kind, r.target)).collect();
        assert_eq!(kinds, [
            (RuleKind::App, Target::Direct),
            (RuleKind::Geosite, Target::Block),
            (RuleKind::Geosite, Target::Direct),
            (RuleKind::Geoip, Target::Direct),
        ]);
    }
}
