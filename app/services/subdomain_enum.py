"""
Subdomain Enumeration Service for QUADSEER v3.0
Sources: crt.sh (free, no API key), DNS brute force, and CNAME chaining.
"""

import asyncio
import httpx
import dns.resolver
import dns.exception
from typing import List, Set, Dict, Any
from sqlalchemy.orm import Session
from app.models import Scan, Finding
from app.core.config import get_settings

settings = get_settings()

# Common subdomains for brute force
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "imap", "test", "vpn", "api", "dev", "staging", "demo",
    "admin", "portal", "webdisk", "cpanel", "whm", "webmin", "mx", "mx1",
    "mx2", "autodiscover", "autoconfig", "m", "mobile", "blog", "shop",
    "store", "support", "help", "docs", "wiki", "forum", "chat", "app",
    "cdn", "static", "assets", "media", "img", "images", "css", "js",
    "beta", "alpha", "preprod", "prod", "production", "uat", "qa",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "build", "deploy",
    "grafana", "prometheus", "kibana", "elk", "monitor", "monitoring",
    "nagios", "zabbix", "sentry", "status", "health", "metrics",
    "db", "database", "mysql", "postgres", "redis", "mongo", "mongodb",
    "elastic", "elasticsearch", "kafka", "rabbitmq", "mq",
    "internal", "intranet", "extranet", "private", "secure", "auth",
    "login", "sso", "idp", "oauth", "ldap", "ad", "active-directory",
    "vpn", "remote", "rdp", "ssh", "sftp", "ftp", "ftps",
    "backup", "bak", "archive", "old", "legacy", "v1", "v2", "v3",
    "api-v1", "api-v2", "rest", "graphql", "soap", "ws", "websocket",
    "webdav", "caldav", "carddav", "exchange", "owa", "outlook",
    "sharepoint", "teams", "lync", "skype", "zoom", "jitsi",
    "confluence", "jira", "trello", "asana", "notion", "slack",
    "mattermost", "rocket", "zulip", "discord", "irc",
    "kubernetes", "k8s", "kube", "rancher", "openshift", "docker",
    "swarm", "nomad", "consul", "vault", "etcd", "coredns",
    "traefik", "nginx", "apache", "haproxy", "varnish", "squid",
    "cloud", "aws", "azure", "gcp", "digitalocean", "linode",
    "heroku", "netlify", "vercel", "firebase", "appengine",
    "s3", "bucket", "storage", "blob", "file", "files", "upload",
    "download", "transfer", "sync", "backup", "snapshot", "restore",
    "analytics", "tracking", "pixel", "beacon", "tag", "gtm",
    "ads", "ad", "advertising", "campaign", "marketing", "email",
    "newsletter", "mailchimp", "sendgrid", "postmark", "ses",
    "stripe", "paypal", "braintree", "payment", "checkout", "billing",
    "invoice", "subscription", "plan", "pricing", "quote",
    "crm", "salesforce", "hubspot", "pipedrive", "zoho", "freshsales",
    "erp", "sap", "oracle", "dynamics", "netsuite", "workday",
    "hr", "hrms", "payroll", "benefits", "recruiting", "ats",
    "learning", "lms", "training", "compliance", "policy",
    "survey", "feedback", "review", "rating", "testimonial",
    "careers", "jobs", "apply", "talent", "workday", "greenhouse",
    "lever", "workable", "bamboohr", "zenefits", "gusto",
    "zendesk", "freshdesk", "intercom", "drift", "crisp", "tawk",
    "livechat", "olark", "purechat", "snapengage", "comm100",
    "calendly", "acuity", "square", "bookings", "appointments",
    "events", "webinar", "conference", "summit", "meet",
    "video", "stream", "live", "broadcast", "tv", "radio",
    "podcast", "audio", "music", "sound", "playlist", "album",
    "news", "press", "media", "pr", "communications", "public",
    "investor", "ir", "sec", "financial", "annual", "report",
    "compliance", "legal", "privacy", "terms", "gdpr", "ccpa",
    "security", "sec", "infosec", "cyber", "threat", "intel",
    "bugbounty", "hackerone", "bugcrowd", "intigriti", "yeswehack",
    "cobalt", "synack", "hackenproof", "immunefi", "openbugbounty",
]


async def fetch_crtsh(domain: str) -> Set[str]:
    """Query crt.sh Certificate Transparency logs. Free, no API key."""
    subdomains = set()
    try:
        async with httpx.AsyncClient(timeout=45.0, follow_redirects=True) as client:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "").strip().lower()
                    # crt.sh returns wildcards like *.example.com
                    if name.startswith("*."):
                        name = name[2:]
                    if name and name.endswith(f".{domain}") and name != domain:
                        subdomains.add(name)
            else:
                print(f"crt.sh returned HTTP {response.status_code}")
    except httpx.TimeoutException:
        print("crt.sh query timed out")
    except Exception as e:
        print(f"crt.sh error: {e}")
    return subdomains


async def dns_resolve(subdomain: str) -> Dict[str, Any]:
    """Resolve a subdomain via DNS. Returns record info or None."""
    result = {"subdomain": subdomain, "records": {}, "resolvable": False}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
    for rtype in record_types:
        try:
            answers = resolver.resolve(subdomain, rtype)
            result["records"][rtype] = [str(r) for r in answers]
            result["resolvable"] = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.Timeout, dns.exception.DNSException):
            continue
        except Exception:
            continue

    return result


async def brute_force_subdomains(domain: str, max_concurrent: int = 50) -> List[Dict[str, Any]]:
    """Brute force common subdomains with concurrency limit."""
    semaphore = asyncio.Semaphore(max_concurrent)
    results = []

    async def check_one(sub: str):
        async with semaphore:
            full = f"{sub}.{domain}"
            return await dns_resolve(full)

    tasks = [check_one(sub) for sub in COMMON_SUBDOMAINS]
    resolved = await asyncio.gather(*tasks, return_exceptions=True)

    for r in resolved:
        if isinstance(r, dict) and r.get("resolvable"):
            results.append(r)

    return results


async def subdomain_scan_target(scan: Scan, db: Session):
    """
    Subdomain enumeration scan.
    Combines crt.sh CT logs + DNS brute force.
    """
    target = scan.target.target
    findings = []
    all_subdomains: Set[str] = set()

    # ── Phase 1: Certificate Transparency (crt.sh) ──
    ct_subs = await fetch_crtsh(target)
    all_subdomains.update(ct_subs)

    ct_count = len(ct_subs)
    findings.append(Finding(
        scan_id=scan.id,
        title=f"Certificate Transparency: {ct_count} subdomains found",
        description=f"crt.sh returned {ct_count} unique subdomains for {target} from SSL/TLS certificate logs.",
        severity="info" if ct_count > 0 else "low",
        source="crt.sh",
        raw_data={"subdomains": sorted(ct_subs), "count": ct_count},
        confidence="high"
    ))

    # ── Phase 2: DNS Brute Force ──
    brute_results = await brute_force_subdomains(target)
    brute_subs = {r["subdomain"] for r in brute_results}
    all_subdomains.update(brute_subs)

    brute_count = len(brute_results)
    findings.append(Finding(
        scan_id=scan.id,
        title=f"DNS Brute Force: {brute_count} subdomains resolved",
        description=f"Resolved {brute_count} subdomains from {len(COMMON_SUBDOMAINS)} common names tested.",
        severity="info" if brute_count > 0 else "low",
        source="dns_bruteforce",
        raw_data={"resolved": brute_results, "count": brute_count},
        confidence="high"
    ))

    # ── Phase 3: Per-subdomain detail findings ──
    new_discovered = brute_subs - ct_subs
    if new_discovered:
        findings.append(Finding(
            scan_id=scan.id,
            title=f"{len(new_discovered)} subdomains only in DNS brute force",
            description=f"Subdomains found via brute force but NOT in certificate transparency: {', '.join(sorted(new_discovered)[:10])}{'...' if len(new_discovered) > 10 else ''}",
            severity="medium",
            source="dns_bruteforce",
            raw_data={"new_subdomains": sorted(new_discovered)},
            confidence="high"
        ))

    # ── Phase 4: Aggregate summary ──
    total = len(all_subdomains)
    findings.append(Finding(
        scan_id=scan.id,
        title=f"Total Subdomains Discovered: {total}",
        description=f"Combined CT logs + DNS brute force found {total} unique subdomains for {target}.",
        severity="high" if total > 20 else "medium" if total > 5 else "low",
        source="subdomain_enum",
        raw_data={
            "total": total,
            "from_ct": ct_count,
            "from_brute": brute_count,
            "all_subdomains": sorted(all_subdomains)
        },
        confidence="high"
    ))

    # Mark wildcard detection
    wildcard_test = f"this-should-not-exist-{hash(target) % 10000:04d}.{target}"
    wildcard_result = await dns_resolve(wildcard_test)
    if wildcard_result["resolvable"]:
        findings.append(Finding(
            scan_id=scan.id,
            title="Wildcard DNS Detected",
            description=f"{target} appears to have a wildcard DNS record. Brute force results may include false positives.",
            severity="info",
            source="dns_bruteforce",
            confidence="high"
        ))

    db.add_all(findings)
    db.commit()

    return findings
