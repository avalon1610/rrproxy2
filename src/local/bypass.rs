use std::net::IpAddr;

use hyper::Uri;
use ipnetwork::IpNetwork;
use tracing::debug;

pub(crate) struct Bypass {
    cidr: Vec<IpNetwork>,
    domains: Vec<String>,
}

impl Bypass {
    pub(crate) fn new(rules: impl AsRef<str>) -> Self {
        let rules = rules.as_ref();
        let mut cidr = Vec::new();
        let mut domains = Vec::new();

        for rule in rules.split(',') {
            if let Ok(ip_network) = rule.parse::<IpNetwork>() {
                cidr.push(ip_network);
            } else {
                domains.push(rule.to_string());
            }
        }

        Self { cidr, domains }
    }

    pub(crate) fn check(&self, url: &Uri) -> bool {
        if self.cidr.is_empty() && self.domains.is_empty() {
            return false;
        }

        let host = url.host().unwrap_or_default();
        if let Ok(ip) = host.parse::<IpAddr>() {
            for cidr in &self.cidr {
                if cidr.contains(ip) {
                    debug!("Bypass CIDR match: {cidr} contains {ip}");
                    return true;
                }
            }
        } else {
            for domain in &self.domains {
                if host.contains(domain) {
                    debug!("Bypass domain match: {domain} contains {host}");
                    return true;
                }
            }
        }

        false
    }
}
