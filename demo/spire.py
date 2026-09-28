"""Finding the SVID that names a particular agent.

One module rather than a copy in each script: the rule it implements is easy to
get wrong in a way that still looks like it works. A selector such as
``unix:uid:1000`` matches every entry that user owns, so the Workload API hands
back several SVIDs and ``svid.0.pem`` is simply whichever SPIRE answered with
first. Reading that one binds the wrong identity and reports success.
"""

from __future__ import annotations

import glob
import os
import subprocess
import time

__all__ = ["spiffe_id_of", "svid_naming", "svid_count", "fetch_svid"]


def spiffe_id_of(pem_path: str) -> str:
    """The URI SAN of a certificate, or "" when it has none."""
    from cryptography import x509

    try:
        with open(pem_path, "rb") as handle:
            cert = x509.load_pem_x509_certificate(handle.read())
    except (OSError, ValueError):
        return ""
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return ""
    for san in sans:
        if isinstance(san, x509.UniformResourceIdentifier):
            return san.value
    return ""


def svid_naming(svid_dir: str, ulid: str) -> str:
    """The path of the SVID whose SPIFFE ID names this agent, or ""."""
    for path in sorted(glob.glob(os.path.join(svid_dir, "svid.*.pem"))):
        if f"/agents/{ulid}/" in spiffe_id_of(path):
            return path
    return ""


def svid_count(svid_dir: str) -> int:
    return len(glob.glob(os.path.join(svid_dir, "svid.*.pem")))


def fetch_svid(agent_bin: str, socket: str, svid_dir: str, ulid: str,
               attempts: int = 20, delay: float = 1.0) -> str:
    """Fetch through the Workload API until an SVID naming this agent appears.

    The loop is not defensive padding. A registration entry is created on the
    server, and the agent learns about it on its own sync interval: fetching
    once, immediately, usually returns the SVIDs the agent already held and none
    for the entry just made. A caller that gave up there would report "no SVID
    names you" for a workload that gets one two seconds later, and the bind would
    silently fall back to a runtime the agent describes about itself.

    Returns the path of the SVID naming ``ulid``, or "" if none arrives in time.
    """
    os.makedirs(svid_dir, exist_ok=True)
    for _ in range(max(1, attempts)):
        subprocess.run([agent_bin, "api", "fetch", "x509", "-socketPath", socket,
                        "-write", svid_dir], capture_output=True, text=True)
        pem = svid_naming(svid_dir, ulid)
        if pem:
            return pem
        time.sleep(delay)
    return ""
