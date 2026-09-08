# FreeBSD 15.1 Migration Compatibility Checker

A single-file, dependency-free C++20 tool that scans your **current Linux
system's hardware** and produces a scored report estimating how well it
would work after migrating to **FreeBSD 15.1**.

It reads real hardware/configuration data directly from `/proc` and `/sys`
(no `lspci`/`lsusb`/other external commands are shelled out to), and scores
each item against FreeBSD's actual current driver support — not Linux's.

```
================================================================
   FreeBSD 15.1 Migration Compatibility Checker
   Privilege mode: normal user (least privilege)
================================================================

  -- CPU
  |  *  [0] FULLY COMPATIBLE   12th Gen Intel(R) Core(TM) i7-12650H
  |     -> Intel | 16 logical cores | architecture: x86_64
  |     FreeBSD 15.1 has mature, first-class support for x86_64...
```

## Why this exists

Generic "is my hardware Linux-compatible" checkers don't help much once
you're *already* on Linux and wondering whether a specific, less mainstream
target — FreeBSD — will treat the same hardware as well. This tool answers
that specific question, using what's actually known about FreeBSD 15.1's
driver maturity today (Intel graphics via `i915kms`, NVIDIA's proprietary
driver limitations under Wayland, Realtek/MediaTek Wi-Fi gaps, and so on).

## Build

Requires a C++20 compiler (GCC 12+ or Clang 15+). No external libraries.

```sh
g++ -O2 -Wall -Wextra -std=c++20 freebsd_compat_checker.cpp -o freebsd_compat_checker
```

## Usage

```sh
./freebsd_compat_checker                  # print the report to the terminal
./freebsd_compat_checker --save report.txt  # also save a plain-text copy
./freebsd_compat_checker --help
```

No root privileges are required. Running as root only unlocks a few
firmware-adjacent checks (see [Privilege mode](#privilege-mode) below); the
tool always runs at least a full scan without it.

## What it checks

| Category | What it looks at | Source |
|---|---|---|
| CPU | Vendor, model, core count, architecture | `/proc/cpuinfo`, `uname()` |
| Memory | Total RAM | `/proc/meminfo` |
| Storage | Storage device type (NVMe/SATA/HDD) **and**, separately, actual unpartitioned disk space | `statvfs()`, `/proc/self/mountinfo`, `/sys/block/*` |
| Graphics | Every PCI display controller, its vendor, and its current Linux driver | `/sys/bus/pci/devices/*` |
| Networking | Every physical (non-virtual) network interface and its driver | `/sys/class/net/*` |
| Audio | ALSA-registered sound cards | `/proc/asound/cards` |
| Firmware | UEFI vs. legacy BIOS | `/sys/firmware/efi` |
| Secure Boot | Current Secure Boot state (informational only) | `/sys/firmware/efi/efivars` |
| TPM | Presence of a TPM device | `/sys/class/tpm`, `/dev/tpm0` |
| Power | Battery presence/status (laptops) | `/sys/class/power_supply/BAT*` |
| Virtualization | Whether the scan itself is running inside a VM | `/proc/cpuinfo` hypervisor flag, DMI |
| Online | Basic outbound TCP/443 reachability (no DNS/HTTP involved) | raw socket probe |

### Storage is split into two separate items on purpose

A full disk and incompatible hardware are two different problems. This tool
reports them separately so a nearly-full but perfectly FreeBSD-compatible
NVMe drive doesn't get scored the same as, say, an unsupported storage
controller:

- **"Storage device: ..."** — is the storage *hardware* (NVMe/SATA/HDD)
  natively supported by FreeBSD? This is almost always `FULLY COMPATIBLE`.
- **"Installation space: ..."** — is there actually room to *install*
  FreeBSD right now (an unpartitioned gap on the disk, not filesystem free
  space)? This is a logistics note, not a hardware verdict, and is marked
  non-critical so it doesn't distort the overall compatibility score.

## Scoring

Each item gets one of four scores:

| Score | Meaning |
|---|---|
| `[0] FULLY COMPATIBLE` | No concerns |
| `[1] COMPATIBLE (minor)` | Works, but with caveats worth knowing about |
| `[2] MAYBE INCOMPATIBLE` | Real uncertainty — verify before migrating |
| `[3] INCOMPATIBLE` | Expect this to be a real problem |

Items marked `critical` (CPU, RAM, primary storage type, GPU) count double
toward the overall percentage shown in the summary.

## Privilege mode

The tool detects (via `geteuid()`) whether it's running as root, but never
requires it:

- **As a normal user (recommended default):** runs the full scan. A couple
  of restricted nodes (e.g. some `efivarfs` entries) may be unreadable and
  are reported as "unavailable" rather than guessed at.
- **As root:** the same scan, with those few restricted nodes now
  readable. Useful as an optional second pass if the normal-user run
  reported something as unavailable.

## Known limitations

- This tool reflects *driver/hardware* compatibility as currently
  understood; it cannot predict application-level bugs, and FreeBSD's own
  support matrix changes over time — treat scores as a starting point for
  research, not a guarantee.
- Wayland support for NVIDIA hybrid graphics on FreeBSD is explicitly
  called out as limited, matching the current state as of FreeBSD 15.1.
- The audio section reflects widely-reported community experience that
  FreeBSD's native sound stack is less polished than Linux's; installing
  PipeWire is suggested there for a more modern experience, and separately
  because Wayland's screen-capture/screen-sharing protocol (used by tools
  like Spectacle) depends on it — not on audio at all.
- Network driver recognition is based on the *Linux* driver name currently
  bound to each interface, used only as a hint toward the likely chipset —
  it does not query FreeBSD's driver database directly.
