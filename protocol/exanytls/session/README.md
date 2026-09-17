# ExAnyTLS session implementation

This package is a TCP-only copy of `github.com/anytls/sing-anytls/session`
from v0.0.11, licensed under GPL-3.0-or-later like sing-box itself.

It stays wire-compatible with AnyTLS session version 2 and preserves the
upstream session-pool lifecycle: each active proxy stream leases one session,
and a closed stream returns that session to the idle pool. Every pooled AnyTLS
session uses its own resumable extrojan logical session as the underlying
`net.Conn`.

The fork adds recovery-aware control/SYNACK timeouts, synchronization for
concurrent transport activity, direct client metadata support, and splitting
writes larger than the protocol's 16-bit frame length.
