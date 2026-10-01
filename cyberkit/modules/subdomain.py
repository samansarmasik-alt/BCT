"""Subdomain discovery by dictionary resolution.

Prefixes a builtin wordlist of roughly 180 common labels onto each
registrable domain and resolves them with the stdlib resolver, so there is no
brute-force dependency. The module is scope-gated: a candidate name is only
ever resolved when :meth:`Scope.permits` already accepts it, and names outside
the declared boundary are only counted, never queried.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket

from ..core.http import split_host_port
from ..core.models import Finding, Host
from ..core.module import Module, register

#: Wall-clock budget for a single label lookup. Most candidates do not exist,
#: so this bounds the slow NXDOMAIN path without cutting off a live answer.
RESOLVE_BUDGET = 2.0

#: Common prefixes that resolve on real estates far more often than random ones.
WORDS: tuple[str, ...] = (
    "www", "api", "dev", "staging", "test", "admin", "mail", "vpn", "git",
    "jenkins", "ci", "cd", "deploy", "internal", "beta", "alpha", "demo",
    "portal", "cdn", "static", "assets", "img", "ns1", "ns2", "smtp", "ftp",
    "blog", "shop", "m", "mobile", "auth", "sso", "id", "oauth", "grafana",
    "kibana", "prometheus", "jira", "confluence", "gitlab", "bitbucket",
    "build", "registry", "docker", "k8s", "kube", "mongo", "redis", "mysql",
    "db", "backup", "db01", "old", "legacy", "new", "backup2", "preprod",
    "prod", "uat", "qa", "sandbox", "play", "preview", "devops", "sec",
    "security", "monitor", "monitoring", "status", "health", "metrics",
    "proxy", "gateway", "edge", "lb", "load", "cache", "search", "elastic",
    "solr", "rabbit", "kafka", "zookeeper", "vault", "consul", "etcd", "log",
    "logs", "splunk", "sentry", "bugzilla", "redmine", "rocket", "chat", "im",
    "matrix", "sync", "files", "share", "cloud", "s3", "storage", "download",
    "dl", "mirror", "updates", "update", "patch", "patches", "docs", "doc",
    "wiki", "kb", "help", "support", "desk", "tickets", "crm", "erp", "hr",
    "payroll", "finance", "billing", "invoice", "payment", "pay", "checkout",
    "cart", "order", "orders", "shipping", "track", "maps", "map",
    "analytics", "data", "bi", "ml", "ai", "seo", "ads", "marketing",
    "campaign", "newsletter", "subscribe", "feedback", "survey", "forms",
    "form", "register", "signup", "login", "signin", "account", "profile",
    "settings", "console", "panel", "manage", "manager", "adminer",
    "phpmyadmin", "dbadmin", "dashboard", "dashboard2", "nagios", "zabbix",
    "cacti", "webmin", "phpldapadmin", "gitweb", "cvs", "svn", "hg",
    "source", "sources", "repo", "repos", "repositories", "backup1", "sql",
    "dump", "seed", "migrate", "migration", "job", "jobs", "cron", "queue",
    "worker", "workers", "batch", "report", "reports", "insight", "insights",
    "warehouse", "bi2", "cube", "olap", "spark", "hadoop", "hdfs", "hive",
    "presto", "trino", "superset", "metabase", "tableau", "powerbi", "etc",
)


@register
class SubdomainModule(Module):
    name = "subdomain"
    description = "Resolve a common-label wordlist against each domain, scope-gated"
    tags = ("recon", "dns")

    async def run(self, targets: list[str]) -> list[Host]:
        return list(await asyncio.gather(*(self._scan(t) for t in targets)))

    async def _scan(self, target: str) -> Host:
        host, _port = split_host_port(target)
        host = host.strip().rstrip(".").lower()
        record = Host(target=host or target)

        if not host or self._is_ip(host):
            record.notes.append(
                "target has no registrable domain (IP literal or empty host); skipped"
            )
            return record

        record.notes.append(f"wordlist of {len(WORDS)} labels against {host}")
        candidates = [f"{label}.{host}" for label in WORDS]
        # Scope before resolving: an unauthorized name must never be queried.
        in_scope = [name for name in candidates if self.scope.permits(name)]
        denied = len(candidates) - len(in_scope)
        if denied:
            record.notes.append(f"{denied} candidates outside scope were not queried")

        semaphore = asyncio.Semaphore(max(1, self.config.concurrency))
        results = await asyncio.gather(
            *(self._resolve(name, semaphore) for name in in_scope),
            return_exceptions=True,
        )

        found = 0
        for name, result in zip(in_scope, results, strict=True):
            if isinstance(result, BaseException) or not result:
                continue
            found += 1
            record.hostnames.append(name)
            for address in result:
                if address not in record.addresses:
                    record.addresses.append(address)
            record.findings.append(
                Finding(
                    title=f"Subdomain discovered: {name}",
                    severity="info",
                    module=self.name,
                    target=host,
                    detail="resolved to " + ", ".join(result),
                )
            )

        record.hostnames.sort()
        record.notes.append(f"{found}/{len(candidates)} candidates resolved")
        return record

    @staticmethod
    def _is_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return False
        return True

    async def _resolve(self, name: str, semaphore: asyncio.Semaphore) -> list[str]:
        """Return the A/AAAA addresses of ``name``, or an empty list.

        Each candidate is one blocking resolver call. Almost all of them are
        NXDOMAIN, and a slow resolver answers those at the pace of its own
        timeout, so every lookup runs under a wall-clock budget. Without it a
        180-label list against a domain with a lazy resolver took 12 seconds.
        """
        async with semaphore:
            try:
                infos = await asyncio.wait_for(
                    asyncio.to_thread(socket.getaddrinfo, name, None),
                    timeout=RESOLVE_BUDGET,
                )
            except (TimeoutError, socket.gaierror, UnicodeError, OSError):
                return []
        addresses = {str(info[4][0]) for info in infos}
        return sorted(addresses)
