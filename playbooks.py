"""Server-side playbook allowlist and target validation for response jobs.

Only the playbooks listed here can run. Each one is pinned by its SHA-256 digest: if a file on disk changes, the
executor refuses to run it until this list is updated in a reviewed change. Analysts choose an action, never a
playbook path, and every target is validated against a strict pattern before it can reach a command.
"""
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

PLAYBOOK_ROOT = (Path(__file__).resolve().parent / "ansible" / "playbooks").resolve()
MEDICAL_CLASSES = ("mri", "ct", "x_ray", "ultrasound", "ventilator", "patient_monitor", "infusion_pump")
TIERS = ("read_only", "disruptive")

_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")       # hostname labels: no spaces, slashes, braces or quotes
_ACCOUNT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
_TENANT = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")


@dataclass(frozen=True)
class Playbook:
    action: str
    playbook_id: str
    version: str
    tier: str        # read_only | disruptive (disruptive needs a second person to approve)
    target: str      # host | ip | account
    file: str        # path under ansible/playbooks/
    sha256: str      # pinned digest of the approved file


ALLOWLIST = {
    "isolate_host": Playbook("isolate_host", "contain.isolate_host", "1.0.0", "disruptive", "host",
                             "contain/isolate_host.yml",
                             "ce31c1622dd0cae912e893c9a871f69a8529b4fe553c1fec2383add680663029"),
    "disable_account": Playbook("disable_account", "contain.disable_account", "1.0.0", "disruptive", "account",
                                "contain/disable_account.yml",
                                "c976b6eb8b63af7c1475158112bb284131cf2b7fd3b4719f22ef8a49f43e27d1"),
    "block_ip": Playbook("block_ip", "contain.block_ip", "1.0.0", "disruptive", "ip",
                         "contain/block_ip.yml",
                         "3467af64855eabee15cd5e8b4fa28520ae961d52af1338cc81834a2e701f4ed6"),
}


class TargetRefused(ValueError):
    """The action or target is not acceptable. The message is safe to show the analyst."""


def playbook_for(action):
    pb = ALLOWLIST.get(action)
    if pb is None:
        raise TargetRefused("action has no approved playbook")
    return pb


def validate_target(action, raw):
    """Return the normalized target, or raise TargetRefused. Nothing else is ever passed to a command."""
    pb = playbook_for(action)
    if not isinstance(raw, str) or not raw.strip():
        raise TargetRefused("target must be text")
    value = raw.strip()
    if pb.target == "ip":
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            raise TargetRefused("target must be an IP address")
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            raise TargetRefused("target address cannot be blocked")
        return str(ip)
    if pb.target == "host":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
        if not _HOST.fullmatch(value):
            raise TargetRefused("target must be a host name or IP address")
        return value
    if not _ACCOUNT.fullmatch(value):
        raise TargetRefused("target must be an account name")
    return value


def valid_tenant(tenant):
    return isinstance(tenant, str) and bool(_TENANT.fullmatch(tenant))


def digest_of(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verified_path(pb):
    """The playbook file, if it is inside the playbook root and matches its pinned digest. Otherwise RuntimeError."""
    path = (PLAYBOOK_ROOT / pb.file).resolve()
    if PLAYBOOK_ROOT not in path.parents or not path.is_file():
        raise RuntimeError("playbook is missing or outside the playbook directory")
    if digest_of(path) != pb.sha256:
        raise RuntimeError("playbook does not match its approved digest")
    return path
