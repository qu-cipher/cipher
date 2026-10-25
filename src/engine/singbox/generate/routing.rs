//! Routing rules and presets → route rules, rule sets and matching DNS rules.

use super::{DIRECT_TAG, DNS_LOCAL_TAG, DNS_REMOTE_TAG, PROXY_TAG};
use crate::engine::singbox::config::{
    dns::{DnsRule, DnsRuleAction},
    route::{RemoteRuleSet, RouteRule, RuleAction, RuleSet, RuleSetFormat},
};
use crate::routing::{Rule, RuleKind, Routing, Target};

const GEOSITE_URL: &str = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set";
const GEOIP_URL: &str = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set";

#[derive(Default)]
pub(super) struct Routed {
    pub rules: Vec<RouteRule>,
    pub rule_sets: Vec<RuleSet>,
    pub dns_rules: Vec<DnsRule>,
}

/// `resolve_ips`: the inbound only sees domain names (proxy modes), so IP rules
/// need a `resolve` action before them to match anything.
pub(super) fn build(routing: &Routing, resolve_ips: bool) -> Routed {
    let mut routed = Routed::default();
    let mut resolved = !resolve_ips;

    for rule in routing.effective_rules() {
        if !resolved && rule.kind.matches_ip() {
            routed.rules.push(RouteRule { action: Some(RuleAction::Resolve), ..Default::default() });
            resolved = true;
        }
        if matches!(rule.kind, RuleKind::Geosite | RuleKind::Geoip) {
            for value in &rule.values {
                add_rule_set(&mut routed.rule_sets, rule.kind, value);
            }
        }
        routed.rules.extend(route_rules(&rule));
        routed.dns_rules.extend(dns_rule(&rule));
    }

    routed
}

fn route_rules(rule: &Rule) -> Vec<RouteRule> {
    let (action, outbound) = match rule.target {
        Target::Proxy => (RuleAction::Route, Some(PROXY_TAG.into())),
        Target::Direct => (RuleAction::Route, Some(DIRECT_TAG.into())),
        Target::Block => (RuleAction::Reject, None),
    };
    let base = RouteRule { action: Some(action), outbound, ..Default::default() };
    let values = Some(rule.values.clone());

    match rule.kind {
        RuleKind::Domain => vec![RouteRule { domain_suffix: values, ..base }],
        RuleKind::Keyword => vec![RouteRule { domain_keyword: values, ..base }],
        RuleKind::Ip => vec![RouteRule { ip_cidr: values, ..base }],
        RuleKind::Geosite | RuleKind::Geoip => vec![RouteRule { rule_set: Some(rule_set_tags(rule)), ..base }],
        // `port` and `port_range` are OR-ed by sing-box, so they share one rule.
        RuleKind::Port => {
            let (ranges, ports): (Vec<_>, Vec<_>) = rule.values.iter().partition(|v| v.contains(':'));
            vec![RouteRule {
                port: non_empty(ports.iter().filter_map(|p| p.parse().ok()).collect()),
                port_range: non_empty(ranges.into_iter().cloned().collect()),
                ..base
            }]
        }
        // `process_name` and `process_path` are AND-ed, so each gets its own rule.
        RuleKind::App => {
            let (paths, names): (Vec<_>, Vec<_>) = rule.values.iter().cloned().partition(|v| v.contains(['/', '\\']));
            [
                non_empty(names).map(|names| RouteRule { process_name: Some(names), ..base.clone() }),
                non_empty(paths).map(|paths| RouteRule { process_path: Some(paths), ..base.clone() }),
            ]
            .into_iter()
            .flatten()
            .collect()
        }
    }
}

/// Domain rules also pick the DNS server, so direct sites get local answers (CDNs nearby)
/// and blocked ones don't resolve. Kept in the same order as the route rules.
fn dns_rule(rule: &Rule) -> Option<DnsRule> {
    let (action, server) = match rule.target {
        Target::Proxy => (DnsRuleAction::Route, Some(DNS_REMOTE_TAG.into())),
        Target::Direct => (DnsRuleAction::Route, Some(DNS_LOCAL_TAG.into())),
        Target::Block => (DnsRuleAction::Reject, None),
    };
    let base = DnsRule { action: Some(action), server, ..Default::default() };
    let values = Some(rule.values.clone());

    match rule.kind {
        RuleKind::Domain => Some(DnsRule { domain_suffix: values, ..base }),
        RuleKind::Keyword => Some(DnsRule { domain_keyword: values, ..base }),
        RuleKind::Geosite => Some(DnsRule { rule_set: Some(rule_set_tags(rule)), ..base }),
        _ => None,
    }
}

fn rule_set_tags(rule: &Rule) -> Vec<String> {
    rule.values.iter().map(|code| rule_set_tag(rule.kind, code)).collect()
}

fn rule_set_tag(kind: RuleKind, code: &str) -> String {
    match kind {
        RuleKind::Geoip => format!("geoip-{code}"),
        _ => format!("geosite-{code}"),
    }
}

fn add_rule_set(rule_sets: &mut Vec<RuleSet>, kind: RuleKind, code: &str) {
    let tag = rule_set_tag(kind, code);
    if rule_sets.iter().any(|set| matches!(set, RuleSet::Remote(r) if r.tag == tag)) {
        return;
    }
    let base = if kind == RuleKind::Geoip { GEOIP_URL } else { GEOSITE_URL };
    rule_sets.push(RuleSet::Remote(RemoteRuleSet {
        url: format!("{base}/{tag}.srs"),
        tag,
        format: Some(RuleSetFormat::Binary),
        // GitHub may be blocked on the direct path; the proxy is up when sing-box fetches them.
        download_detour: Some(PROXY_TAG.into()),
        update_interval: None,
    }));
}

fn non_empty<T>(values: Vec<T>) -> Option<Vec<T>> {
    (!values.is_empty()).then_some(values)
}
