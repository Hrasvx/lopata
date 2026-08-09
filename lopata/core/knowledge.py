"""Service knowledge base.

Maps an observed port/service to what its exposure actually means, so the
report can say *why* a listening MariaDB matters and exactly how to close it,
instead of emitting "Open port 3306" and calling it a vulnerability.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .severity import AuthRequirement, Exploitability, Impact

# Logical groupings used by the attack-surface section.
GROUP_WEB = "Public Web"
GROUP_DB = "Databases"
GROUP_ADMIN = "Remote Administration"
GROUP_MAIL = "Email Services"
GROUP_FILE = "File Sharing & Transfer"
GROUP_DIR = "Directory & Authentication"
GROUP_DEV = "Development & Management Interfaces"
GROUP_CACHE = "Caching, Queues & Search"
GROUP_NET = "Network Infrastructure"
GROUP_OTHER = "Other Services"

GROUP_ORDER = (GROUP_DB, GROUP_ADMIN, GROUP_DEV, GROUP_CACHE, GROUP_DIR,
               GROUP_FILE, GROUP_MAIL, GROUP_WEB, GROUP_NET, GROUP_OTHER)

SENSITIVE_GROUPS = (GROUP_DB, GROUP_ADMIN, GROUP_DEV, GROUP_CACHE, GROUP_DIR)


@dataclass
class ServiceProfile:

    title: str
    group: str = GROUP_OTHER
    # Should this ever face the internet?
    public_ok: bool = False
    risk: str = ""
    impact: str = ""
    steps: list[str] = field(default_factory=list)
    verification: str = ""
    references: list[str] = field(default_factory=list)
    exposure_impact: Impact = Impact.INFORMATION
    exploitability: Exploitability = Exploitability.MODERATE
    auth: AuthRequirement = AuthRequirement.NONE
    # Ports where cleartext credentails cross the wire by default.
    cleartext: bool = False


def _db(name: str, port: int, bind_hint: str, extra_steps: list[str]) -> ServiceProfile:
    """Most databases share the same story; only the knobs differ."""
    return ServiceProfile(
        title=f"{name} database exposed to the network",
        group=GROUP_DB,
        public_ok=False,
        risk=(
            f"{name} is listening on TCP/{port} and answers connections from "
            "outside the host. Database engines are designed to sit behind an "
            "application, not in front of the internet: their authentication is "
            "not rate-limited, their wire protocols leak version information "
            "before login, and every historical authentication bypass in the "
            "engine becomes directly reachable."
        ),
        impact=(
            "An attacker can enumerate the version, attempt credential brute "
            "force or reuse without lockout, and exploit any current or future "
            "pre-authentication flaw. Successful access means direct read/write "
            "over application data, bypassing all application-level access "
            "control, and often code execution on the database host."
        ),
        steps=[bind_hint] + extra_steps + [
            f"Block inbound TCP/{port} at the host and network firewall; allow "
            "only the application servers that need it, by source IP.",
            "Require TLS for any connection that must cross a host boundary.",
            "Remove anonymous/default accounts and enforce unique, strong "
            "credentials per application.",
        ],
        verification=(
            f"From an unrelated host run `nc -vz <target> {port}` — it must not "
            f"connect. From the application host, confirm the app still works."
        ),
        exposure_impact=Impact.LIMITED,
        exploitability=Exploitability.EASY,
        auth=AuthRequirement.NONE,
    )


_PROFILES: dict[int, ServiceProfile] = {
    21: ServiceProfile(
        title="FTP service exposed",
        group=GROUP_FILE, cleartext=True,
        risk=("FTP transmits credentials and file contents in cleartext and is "
              "commonly left with anonymous access enabled."),
        impact=("Anyone on the network path can capture credentials, and "
                "anonymous access may expose or allow overwriting of served "
                "content."),
        steps=["Replace FTP with SFTP (over SSH) or FTPS.",
               "If FTP must remain, disable anonymous login and enforce "
               "explicit TLS (FTPS) for both control and data channels.",
               "Restrict inbound TCP/21 and the passive port range by source IP."],
        verification="Confirm `ftp <target>` no longer accepts the `anonymous` "
                     "user, and that plaintext AUTH is rejected.",
        exposure_impact=Impact.LIMITED,
        exploitability=Exploitability.EASY,
    ),
    22: ServiceProfile(
        title="SSH service exposed",
        group=GROUP_ADMIN, public_ok=True,
        risk=("SSH provides interactive administrative access to the host. "
              "Publicly reachable SSH is continuously targeted by automated "
              "credential-stuffing and brute-force traffic."),
        impact=("A single reused or weak password — or a compromised key — "
                "yields shell access and, from there, the whole host. Exposure "
                "also reveals the OpenSSH version, letting an attacker wait for "
                "the next advisory."),
        steps=["Disable password authentication entirely "
               "(`PasswordAuthentication no`) and use keys or certificates.",
               "Disable direct root login (`PermitRootLogin no`).",
               "Restrict inbound TCP/22 to known management ranges, or place it "
               "behind a VPN / bastion host.",
               "Deploy fail2ban or equivalent rate limiting.",
               "Keep OpenSSH patched — it is a frequent advisory target."],
        verification="Run `ssh -o PreferredAuthentications=password <target>` "
                     "and confirm the server refuses password auth.",
        exposure_impact=Impact.LIMITED,
        exploitability=Exploitability.MODERATE,
        auth=AuthRequirement.USER,
    ),
    23: ServiceProfile(
        title="Telnet service exposed",
        group=GROUP_ADMIN, cleartext=True,
        risk=("Telnet carries credentials and session data in plaintext and has "
              "no integrity protection whatsoever."),
        impact=("Anyone able to observe the network path recovers "
                "administrative credentials verbatim and can hijack the session."),
        steps=["Disable telnetd and remove the package.",
               "Use SSH for all remote administration.",
               "Block inbound TCP/23 at the firewall."],
        verification="`nc -vz <target> 23` must fail to connect.",
        exposure_impact=Impact.SERIOUS,
        exploitability=Exploitability.EASY,
    ),
    25: ServiceProfile(
        title="SMTP service exposed",
        group=GROUP_MAIL, public_ok=True,
        risk=("An internet-facing MTA must accept mail from strangers, so the "
              "risk is not exposure itself but misconfiguration: open relaying, "
              "missing TLS, and user enumeration via VRFY/EXPN."),
        impact=("An open relay gets the host blacklisted and used for phishing. "
                "Missing STARTTLS exposes mail contents in transit. VRFY/EXPN "
                "leak valid account names for credential attacks."),
        steps=["Verify the server is not an open relay before anything else.",
               "Enforce STARTTLS and publish MTA-STS.",
               "Disable the VRFY and EXPN commands.",
               "Require authentication on the submission ports (587/465) and "
               "rate-limit failures.",
               "Publish SPF, DKIM and DMARC records."],
        verification="Attempt a relay from an unrelated host to an unrelated "
                     "domain; the server must reject it with 5xx.",
        exposure_impact=Impact.LIMITED,
        exploitability=Exploitability.MODERATE,
    ),
    53: ServiceProfile(
        title="DNS service exposed",
        group=GROUP_NET, public_ok=True,
        risk=("An open recursive resolver can be abused as an amplifier in "
              "reflection attacks, and permissive zone transfers hand over the "
              "internal network map."),
        impact=("Reflection abuse consumes bandwidth and damages reputation; a "
                "successful AXFR reveals every host name in the zone."),
        steps=["Disable recursion for external clients (authoritative servers "
               "should never recurse for the public).",
               "Restrict zone transfers to named secondary servers only.",
               "Enable response rate limiting (RRL).",
               "Consider DNSSEC signing for authoritative zones."],
        verification="`dig @<target> axfr <zone>` must be refused, and a "
                     "recursive query for an unrelated domain must not resolve.",
        exposure_impact=Impact.INFORMATION,
        exploitability=Exploitability.EASY,
    ),
    110: ServiceProfile(
        title="POP3 service exposed",
        group=GROUP_MAIL, public_ok=True, cleartext=True,
        risk="POP3 on 110 without enforced STARTTLS carries mailbox credentials "
             "in cleartext.",
        impact="Network observers recover mailbox credentials and message bodies.",
        steps=["Require STARTTLS on 110 or disable it in favour of POP3S (995).",
               "Enforce rate limiting on authentication failures."],
        verification="Confirm the server rejects USER/PASS before STARTTLS.",
        exposure_impact=Impact.LIMITED,
        exploitability=Exploitability.MODERATE,
    ),
    111: ServiceProfile(
        title="rpcbind / portmapper exposed",
        group=GROUP_NET,
        risk="rpcbind enumerates RPC services and their ports, and is a "
             "well-known DDoS amplification vector.",
        impact="Discloses the RPC service inventory (often NFS) and can be "
               "abused for reflection attacks.",
        steps=["Block TCP/UDP 111 from untrusted networks.",
               "Disable rpcbind if NFS and other RPC services are not in use."],
        verification="`rpcinfo -p <target>` must fail from outside.",
        exposure_impact=Impact.INFORMATION,
        exploitability=Exploitability.EASY,
    ),
    135: ServiceProfile(
        title="MSRPC endpoint mapper exposed",
        group=GROUP_NET,
        risk="The Windows RPC endpoint mapper should never be internet facing; "
             "it enumerates available RPC interfaces.",
        impact="Provides an attacker with a map of callable RPC interfaces and a "
               "long history of remotely exploitable flaws.",
        steps=["Block TCP/135 at the perimeter.",
               "Expose Windows management only over VPN."],
        verification="Port 135 must not answer from outside the management network.",
        exposure_impact=Impact.LIMITED,
        exploitability=Exploitability.DIFFICULT,
    ),
    139: ServiceProfile(
        title="NetBIOS session service exposed",
        group=GROUP_FILE,
        risk="Legacy SMB transport; leaks host and share naming information.",
        impact="Host/share enumeration and a long list of historical SMB flaws.",
        steps=["Block TCP/139 at the perimeter.",
               "Disable NetBIOS over TCP/IP where SMB over 445 suffices."],
        verification="Port 139 must not answer from outside.",
        exposure_impact=Impact.LIMITED,
        exploitability=Exploitability.DIFFICULT,
    ),
    143: ServiceProfile(
        title="IMAP service exposed",
        group=GROUP_MAIL, public_ok=True, cleartext=True,
        risk="IMAP on 143 without enforced STARTTLS carries mailbox credentials "
             "in cleartext.",
        impact="Network observers recover mailbox credentials and full mailbox "
               "contents.",
        steps=["Require STARTTLS on 143 or serve IMAPS (993) only.",
               "Rate-limit authentication failures."],
        verification="Confirm LOGIN is refused before STARTTLS is negotiated.",
        exposure_impact=Impact.LIMITED,
        exploitability=Exploitability.MODERATE,
    ),
    161: ServiceProfile(
        title="SNMP service exposed",
        group=GROUP_NET,
        risk="SNMP frequently ships with the default 'public' community string "
             "and, in v1/v2c, no encryption at all.",
        impact="Reads the full device configuration, interface list, routing "
               "table and running processes; with a writable community, "
               "reconfigures the device.",
        steps=["Block UDP/161 from untrusted networks.",
               "Remove default community strings ('public'/'private').",
               "Move to SNMPv3 with authentication and privacy."],
        verification="`snmpwalk -v2c -c public <target>` must time out.",
        exposure_impact=Impact.SERIOUS,
        exploitability=Exploitability.EASY,
    ),
    389: ServiceProfile(
        title="LDAP service exposed",
        group=GROUP_DIR, cleartext=True,
        risk="LDAP on 389 exposes the directory and, without TLS, carries bind "
             "credentials in cleartext. Anonymous bind is often left enabled.",
        impact="Full enumeration of users, groups and organisational structure — "
               "the ideal input for password spraying.",
        steps=["Disable anonymous bind.",
               "Require LDAPS/StartTLS for all binds.",
               "Restrict TCP/389 and 636 to application servers only."],
        verification="`ldapsearch -x -H ldap://<target> -b ''` must be refused.",
        exposure_impact=Impact.SERIOUS,
        exploitability=Exploitability.EASY,
    ),
    445: ServiceProfile(
        title="SMB file sharing exposed",
        group=GROUP_FILE,
        risk="SMB exposed to the internet is one of the most heavily exploited "
             "surfaces in existence (EternalBlue, SMBGhost, ransomware entry).",
        impact="Share enumeration, credential relay attacks, and remote code "
               "execution against unpatched implementations.",
        steps=["Block TCP/445 at the perimeter without exception.",
               "Require SMBv3 with signing and encryption internally.",
               "Disable SMBv1 entirely.",
               "Provide remote file access over VPN instead."],
        verification="`smbclient -L //<target>` must fail from outside.",
        exposure_impact=Impact.TOTAL,
        exploitability=Exploitability.PUBLIC_EXPLOIT,
    ),
    465: ServiceProfile(
        title="SMTPS submission service exposed",
        group=GROUP_MAIL, public_ok=True,
        risk="Implicit-TLS mail submission; must require authentication and must "
             "not relay for unauthenticated senders.",
        impact="An unauthenticated relay is abused for phishing and lands the "
               "host on blocklists.",
        steps=["Require SMTP AUTH over TLS for all submission.",
               "Reject relaying for unauthenticated senders.",
               "Rate-limit and alert on authentication failures."],
        verification="Attempt submission without credentials; it must be rejected.",
        exposure_impact=Impact.LIMITED,
        exploitability=Exploitability.MODERATE,
    ),
    587: ServiceProfile(
        title="SMTP submission service exposed",
        group=GROUP_MAIL, public_ok=True,
        risk="Mail submission port; must enforce STARTTLS and authentication.",
        impact="Without enforced auth the host becomes an open relay; without "
               "enforced TLS, credentials cross the network in the clear.",
        steps=["Enforce STARTTLS before accepting AUTH.",
               "Require authentication for every message accepted.",
               "Rate-limit authentication failures per source."],
        verification="Confirm AUTH is refused on a plaintext connection.",
        exposure_impact=Impact.LIMITED,
        exploitability=Exploitability.MODERATE,
    ),
    993: ServiceProfile(
        title="IMAPS service exposed",
        group=GROUP_MAIL, public_ok=True,
        risk="Encrypted IMAP is expected to be public; the residual risk is "
             "credential brute force against mailboxes.",
        impact="Mailbox takeover if credentials are weak or reused.",
        steps=["Enforce strong passwords and MFA where the mail stack supports it.",
               "Rate-limit failed logins per source address.",
               "Serve only TLS 1.2+ with modern cipher suites."],
        verification="Confirm login throttling triggers after repeated failures.",
        exposure_impact=Impact.INFORMATION,
        exploitability=Exploitability.DIFFICULT,
        auth=AuthRequirement.USER,
    ),
    995: ServiceProfile(
        title="POP3S service exposed",
        group=GROUP_MAIL, public_ok=True,
        risk="Encrypted POP3 is expected to be public; residual risk is "
             "credential brute force.",
        impact="Mailbox takeover if credentials are weak or reused.",
        steps=["Rate-limit failed logins.",
               "Enforce strong passwords.",
               "Serve only TLS 1.2+."],
        verification="Confirm login throttling triggers after repeated failures.",
        exposure_impact=Impact.INFORMATION,
        exploitability=Exploitability.DIFFICULT,
        auth=AuthRequirement.USER,
    ),
    1433: _db("Microsoft SQL Server", 1433,
              "Bind the instance to the private interface and disable the "
              "SQL Browser service (UDP/1434).",
              ["Disable the 'sa' account or give it a unique strong password.",
               "Enable Force Encryption for client connections."]),
    1521: _db("Oracle Database", 1521,
              "Restrict the listener to the private interface via "
              "`VALID_NODE_CHECKING_REGISTRATION_LISTENER`.",
              ["Set a listener password and disable remote listener "
               "administration.",
               "Remove default accounts (SCOTT, DBSNMP) and default passwords."]),
    2049: ServiceProfile(
        title="NFS export exposed",
        group=GROUP_FILE,
        risk="NFS trusts client-supplied UIDs; an exposed export is effectively "
             "an unauthenticated filesystem.",
        impact="Read and often write access to exported data, and privilege "
               "escalation via setuid binaries where root squashing is off.",
        steps=["Restrict exports to specific hosts in /etc/exports.",
               "Enable root_squash and mount exports read-only where possible.",
               "Block TCP/UDP 2049 and 111 at the perimeter.",
               "Prefer NFSv4 with Kerberos (sec=krb5p)."],
        verification="`showmount -e <target>` must fail from an unlisted host.",
        exposure_impact=Impact.SERIOUS,
        exploitability=Exploitability.EASY,
    ),
    2375: ServiceProfile(
        title="Docker daemon API exposed without TLS",
        group=GROUP_DEV,
        risk="The Docker API on 2375 is unauthenticated and grants container "
             "creation with arbitrary host mounts.",
        impact="Trivial full host compromise: an attacker starts a privileged "
               "container mounting the host filesystem and takes root.",
        steps=["Never bind the Docker socket to a network interface.",
               "If remote access is required, use TLS mutual authentication on "
               "2376 with client certificates.",
               "Block 2375/2376 at the firewall immediately."],
        verification="`curl http://<target>:2375/version` must not respond.",
        exposure_impact=Impact.TOTAL,
        exploitability=Exploitability.PUBLIC_EXPLOIT,
    ),
    3306: _db("MySQL/MariaDB", 3306,
              "Set `bind-address = 127.0.0.1` (or the private interface only) "
              "in my.cnf and restart the server.",
              ["Run `DROP USER ''@'localhost'` and remove any anonymous or "
               "wildcard-host accounts (`SELECT user,host FROM mysql.user`).",
               "Require TLS per account with `REQUIRE SSL`."]),
    3389: ServiceProfile(
        title="RDP service exposed",
        group=GROUP_ADMIN,
        risk="Internet-facing RDP is the single most common ransomware entry "
             "point and is continuously brute-forced.",
        impact="Interactive desktop access as a domain user; historically also "
               "pre-authentication RCE (BlueKeep).",
        steps=["Place RDP behind a VPN or an RD Gateway — do not expose it "
               "directly.",
               "Require Network Level Authentication (NLA).",
               "Enforce account lockout policies and MFA.",
               "Restrict TCP/3389 to known management source addresses."],
        verification="Confirm 3389 no longer answers from an external host.",
        exposure_impact=Impact.SERIOUS,
        exploitability=Exploitability.PUBLIC_EXPLOIT,
        auth=AuthRequirement.USER,
    ),
    5432: _db("PostgreSQL", 5432,
              "Set `listen_addresses = 'localhost'` in postgresql.conf and "
              "restart.",
              ["Remove permissive `host all all 0.0.0.0/0` lines from pg_hba.conf "
               "and require `scram-sha-256`.",
               "Enable `ssl = on` and require it in pg_hba.conf (`hostssl`)."]),
    5900: ServiceProfile(
        title="VNC service exposed",
        group=GROUP_ADMIN,
        risk="VNC authentication is an 8-character DES challenge at best and is "
             "frequently left with no password at all.",
        impact="Direct interactive control of the desktop session, often as an "
               "administrative user.",
        steps=["Do not expose VNC directly; tunnel it over SSH or a VPN.",
               "Set a password and enable any available encryption extension.",
               "Bind the VNC server to localhost only."],
        verification="Confirm 5900 does not answer from an external host.",
        exposure_impact=Impact.SERIOUS,
        exploitability=Exploitability.EASY,
    ),
    5984: _db("CouchDB", 5984,
              "Bind to 127.0.0.1 in local.ini.",
              ["Ensure the admin party is closed — an unconfigured CouchDB "
               "grants everyone admin rights."]),
    6379: ServiceProfile(
        title="Redis exposed to the network",
        group=GROUP_CACHE,
        risk="Redis has no authentication by default and its CONFIG command can "
             "write arbitrary files, including SSH keys and cron entries.",
        impact="Unauthenticated read/write of all cached data and, in the common "
               "case, remote code execution on the host.",
        steps=["Set `bind 127.0.0.1` and `protected-mode yes` in redis.conf.",
               "Set a long `requirepass` value, or use ACLs on Redis 6+.",
               "Rename or disable the CONFIG, FLUSHALL and DEBUG commands.",
               "Block TCP/6379 at the firewall."],
        verification="`redis-cli -h <target> ping` must fail or demand auth.",
        exposure_impact=Impact.TOTAL,
        exploitability=Exploitability.PUBLIC_EXPLOIT,
    ),
    8080: ServiceProfile(
        title="Alternate HTTP service exposed",
        group=GROUP_WEB, public_ok=True,
        risk="Port 8080 commonly hosts application servers, management consoles "
             "or staging instances that were never meant to be public.",
        impact="Depends on the application; management consoles on this port "
               "frequently allow deployment of arbitrary code.",
        steps=["Identify what is served here and whether it should be public.",
               "Place non-public applications behind the reverse proxy with "
               "authentication, or firewall the port.",
               "Ensure it is not a staging or debug build of the main site."],
        verification="Fetch the root of the port and confirm the content is "
                     "intended for public consumption.",
        exposure_impact=Impact.INFORMATION,
        exploitability=Exploitability.MODERATE,
    ),
    9200: ServiceProfile(
        title="Elasticsearch exposed to the network",
        group=GROUP_CACHE,
        risk="Elasticsearch historically ships without authentication; the REST "
             "API allows reading and deleting every index.",
        impact="Full disclosure or destruction of all indexed data, which often "
               "includes logs containing credentials and personal data.",
        steps=["Bind to 127.0.0.1 or the private interface "
               "(`network.host` in elasticsearch.yml).",
               "Enable the security features (`xpack.security.enabled: true`) "
               "and set passwords for built-in users.",
               "Put a reverse proxy with authentication in front of any "
               "externally needed endpoint.",
               "Block TCP/9200 and 9300 at the firewall."],
        verification="`curl http://<target>:9200/_cat/indices` must be refused.",
        exposure_impact=Impact.SERIOUS,
        exploitability=Exploitability.EASY,
    ),
    10000: ServiceProfile(
        title="Webmin administration interface exposed",
        group=GROUP_DEV,
        risk="Webmin grants full root-level system administration through a web "
             "UI and has had several pre-authentication RCE advisories.",
        impact="Complete compromise of the host through a single web request or "
               "a guessed password.",
        steps=["Restrict access to management source addresses only.",
               "Place it behind a VPN.",
               "Keep Webmin fully patched and enable two-factor authentication."],
        verification="Confirm port 10000 is unreachable externally.",
        exposure_impact=Impact.TOTAL,
        exploitability=Exploitability.PUBLIC_EXPLOIT,
        auth=AuthRequirement.USER,
    ),
    11211: ServiceProfile(
        title="Memcached exposed to the network",
        group=GROUP_CACHE,
        risk="Memcached has no authentication and its UDP interface is the "
             "largest known DDoS amplification vector.",
        impact="Disclosure of everything held in cache (often session tokens) "
               "and abuse of the host for reflection attacks.",
        steps=["Start with `-l 127.0.0.1` and `-U 0` to disable UDP.",
               "Block TCP/UDP 11211 at the firewall.",
               "Enable SASL authentication if network access is unavoidable."],
        verification="`echo stats | nc -u <target> 11211` must return nothing.",
        exposure_impact=Impact.SERIOUS,
        exploitability=Exploitability.EASY,
    ),
    15672: ServiceProfile(
        title="RabbitMQ management console exposed",
        group=GROUP_DEV,
        risk="The management UI ships with the guest/guest account and exposes "
             "queue contents and broker configuration.",
        impact="Message interception or injection into application queues, and "
               "broker takeover if default credentials remain.",
        steps=["Delete or rename the default guest account.",
               "Bind the management plugin to localhost and reach it via SSH "
               "tunnel.",
               "Restrict TCP/15672 to the management network."],
        verification="Confirm guest/guest is rejected and the port is filtered "
                     "externally.",
        exposure_impact=Impact.SERIOUS,
        exploitability=Exploitability.EASY,
    ),
    27017: _db("MongoDB", 27017,
               "Set `net.bindIp: 127.0.0.1` in mongod.conf.",
               ["Enable authorization (`security.authorization: enabled`) — "
                "MongoDB accepts unauthenticated connections without it.",
                "Create per-application users with least-privilege roles."]),
}


# Service-name fallbacks for ports the table above does not cover.
_BY_NAME: dict[str, int] = {
    "ssh": 22, "telnet": 23, "ftp": 21, "smtp": 25, "submission": 587,
    "smtps": 465, "imap": 143, "imaps": 993, "pop3": 110, "pop3s": 995,
    "domain": 53, "snmp": 161, "ldap": 389, "ldapssl": 636, "microsoft-ds": 445,
    "netbios-ssn": 139, "msrpc": 135, "ms-sql-s": 1433, "oracle": 1521,
    "mysql": 3306, "mariadb": 3306, "postgresql": 5432, "ms-wbt-server": 3389,
    "vnc": 5900, "redis": 6379, "mongodb": 27017, "memcached": 11211,
    "elasticsearch": 9200, "couchdb": 5984, "nfs": 2049, "rpcbind": 111,
}


_WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 3000, 5000}

_GENERIC_WEB = ServiceProfile(
    title="HTTP service exposed",
    group=GROUP_WEB, public_ok=True,
    risk="A web service is reachable on this port. Public web exposure is "
         "expected for the main site, but additional HTTP ports often host "
         "staging builds, admin consoles or forgotten applications.",
    impact="Varies with the application; unintended web endpoints frequently "
           "lack the hardening applied to the primary site.",
    steps=["Confirm the application on this port is meant to be public.",
           "Apply the same authentication, TLS and header hardening as the "
           "primary site, or firewall the port."],
    verification="Fetch the root path and identify the application served.",
    exposure_impact=Impact.INFORMATION,
    exploitability=Exploitability.MODERATE,
)

_GENERIC = ServiceProfile(
    title="Service exposed",
    group=GROUP_OTHER, public_ok=True,
    risk="A network service is listening on this port. Every reachable service "
         "is attack surface that must be intentional and maintained.",
    impact="Unknown without identifying the application behind the port.",
    steps=["Identify the owning application and confirm the exposure is "
           "intentional.",
           "Firewall the port if it is not required from outside the host."],
    verification="Confirm with the service owner that the port must be open.",
    exposure_impact=Impact.NEGLIGIBLE,
    exploitability=Exploitability.NONE,
)


def profile_for(port: int, service_name: str = "") -> ServiceProfile:
    prof = _PROFILES.get(port)
    if prof is not None:
        return prof
    name = (service_name or "").strip().lower()
    mapped = _BY_NAME.get(name)
    if mapped is not None and mapped in _PROFILES:
        return _PROFILES[mapped]
    if port in _WEB_PORTS or name in ("http", "https", "http-alt", "http-proxy"):
        return _GENERIC_WEB
    return _GENERIC


def group_for(port: int, service_name: str = "") -> str:
    return profile_for(port, service_name).group


def is_internal_address(host: str) -> bool:
    """True when the address is not reachable from the public internet.

    `is_global` is the precise test: it excludes RFC1918, loopback,
    link-local, CGNAT and the reserved documentation ranges in one go, which
    is exactly the set an external attacker cannot route to.
    """
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not addr.is_global
