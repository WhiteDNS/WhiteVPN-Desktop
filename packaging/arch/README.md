# Arch Linux

Arch has no use for the `.deb` or `.rpm` the release publishes, so this builds
from the release tarball.

## Building

    cd packaging/arch
    updpkgsums          # fills in the checksums for the release named in pkgver
    makepkg -si

`updpkgsums` matters. The checksums are committed as zeroes so that a release
cannot be packaged without someone deliberately fetching and hashing it — `SKIP`
would let a tampered download install silently, which is not a trade worth making
for a program that carries someone's traffic.

## What works on Linux, and what does not

**The local proxy works.** The app starts the engine, connects, and listens on
`127.0.0.1`. Point a browser or Telegram at it and traffic goes through WhiteVPN.

**The tunnel needs `polkit`.** Creating a tunnel device requires `CAP_NET_ADMIN`,
so the engine — and only the engine — is started through `pkexec`, which puts the
password prompt in the desktop's own polkit agent. The interface stays as the
user. Without polkit installed the app still runs; only the tunnel is
unavailable, and it says so rather than failing quietly.

**Partly verified.** CI brings the adapter up on a real Linux machine, confirms
the routing decision resolves through it, and does so against the same code path
a desktop session takes once its polkit prompt is answered. What that does not
cover is a live connection carrying real traffic, or IPv6 containment measured
the way it was on Windows. Treat Linux tunnel mode as newer than the Windows
one: if traffic does not leave through the node, the local proxy is the reliable
fallback.

## Updating for a release

Change `pkgver`, run `updpkgsums`, and confirm the tarball names in `source_*`
still match what the release publishes.
