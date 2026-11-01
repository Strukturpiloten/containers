"""Fixed inactive source gate for an instrumented nonqualifying direct pair.

A root owner must establish source/FIFO/live-task custody before one token is
written. These constants perform no runtime operation or policy admission.
An extra shell can alter incidental SHLVL/PWD and timing: neither this gate
nor an instrumented startup differential qualifies the original ungated route.
"""

from __future__ import annotations

import hashlib

GUEST_DIRECTORY = "/run/containers-direct-startup"
GUEST_GATE = GUEST_DIRECTORY + "/gate"
GUEST_RELEASE = GUEST_DIRECTORY + "/release"
RELEASE_TOKEN = b"containers-direct-startup-release-v1\n"
ORIGINAL_CMD = ("/usr/local/bin/start-dockerd",)
# Only an inert token is read; the FIFO is never sourced or evaluated. Docker
# supplies its original image environment, with no host environment forwarding.
# The gate-specific shell variable is unexported and removed before exec.
GATE_SOURCE = (
    b"#!/bin/sh\n"
    b"set -eu\n"
    b'[ "$#" -eq 0 ] || exit 125\n'
    b"IFS= read -r containers_direct_release < /run/containers-direct-startup/release\n"
    b'[ "$containers_direct_release" = containers-direct-startup-release-v1 ] || exit 125\n'
    b"unset containers_direct_release\n"
    b"exec /usr/local/bin/start-dockerd\n"
)
GATE_SHA256 = hashlib.sha256(GATE_SOURCE).hexdigest()
