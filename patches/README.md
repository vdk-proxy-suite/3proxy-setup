# Patch status for 3proxy 1.0.0

The installer applies exactly one local patch to the official 3proxy 1.0.0 tag:

- `0004-separate-socks5-reply-buffer.patch` keeps a SOCKS5 parent reply in a
  separate buffer, uses the correct IPv4/IPv6 offsets, and safely consumes a
  domain BND reply using the fixed domain-length offset at `reply[4]`

Three patches shipped by earlier setup releases are intentionally removed:

- `0001-fix-nat-options.patch` is already present upstream in commit `13a5781`
- `0002-fix-one-hop-socks5-udp-parent.patch` must not be replayed over the
  redesigned upstream UDP reconnect/ACL lifecycle; its reply-parser protection
  is retained by the rebased `0004`
- `0005-avoid-second-udp-parent-connect.patch` is superseded by upstream commit
  `eca362a`; retaining it could skip authentication/ACL side effects

The retained patch must be dry-run applied to a clean 1.0.0 source tree and the
direct plus one-hop SOCKS5 UDP regression suite must pass before every release.
Runtime chaining is verified with an IPv4 BND relay; domain/IPv6 reply framing is
covered by wire fixtures because upstream 3proxy stores the UDP relay only for
IPv4/IPv6 address forms and the supported deployment topology is IPv4.
