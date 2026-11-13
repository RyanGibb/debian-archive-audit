# Debian archive audit

Scans of Debian's binary `Packages` indexes, used as evidence for the Debian chapter of Ryan Gibb's PhD thesis (`sections/6-modelling/debian.tex` in pac-paper).
The thesis models Debian's package metadata, including Multi-Arch, and leaves out a few features that Policy does not define, or that dpkg and APT read differently.
These scans check that leaving them out loses nothing in practice: no Debian release since wheezy (2013) uses them.
They also check unstable (sid) at every state since 2012.

## What the thesis claims, and what supports it

| Claim | Release heads | sid since 2012 |
|---|---|---|
| No architecture qualifier on a `Provides` entry | none | 2 packages, for 1–2 days in Dec 2021 (`Provides: nodejs:any`) |
| No `:all` qualifier | none | 1 package, for about 16 hours on 2 May 2014 (`Depends: python:all`) |
| No `:native` qualifier in a binary package | none | none |
| No `:any` Conflicts/Breaks hitting a package that is not `Multi-Arch: allowed` | none | none |
| No explicitly qualified Conflicts/Breaks on a virtual name with a provider at another architecture | none | none |
| No name with two distinct version strings that compare equal (e.g. `1.0` and `1.00`) at one architecture | none | none |
| No malformed stanza: duplicate field, missing `Architecture`, `\|` in Conflicts/Breaks/Provides, non-canonical field case | none (missing `Architecture` not checked) | none |

Explicit qualifiers do occur.
In the sid history there are 204 `:any` Conflicts atoms, all from erlang-doc, and about 23,000 explicitly qualified Conflicts atoms, from the libc6 multilib and cross-toolchain packages.
None of the explicit ones has a provider, so dpkg and APT read them alike.
The `:any` atoms that do name a package which is not `Multi-Arch: allowed` are all in `Replaces`, which the thesis does not model (erlang-src's `Replaces: erlang:any`).

## Layout

- `release-heads/`: one snapshot of each release's indexes.
  - Releases: wheezy, jessie, stretch, buster, bullseye, bookworm, trixie and sid.
  - Architectures: amd64, i386 and arm64 (wheezy has no arm64).
  - Components: main, contrib, non-free and non-free-firmware.
  - `scripts/`: `scan_lib.py` and `scan.py` produce the counts, and `scan2.py` to `scan5.py` are follow-up passes, each described in its docstring. `any_scan.py` counts qualified relation atoms. `eqver.py` looks for distinct version strings that compare equal.
  - `results/`: `<release>.json` holds counts and examples. `passes/` holds the output of `scan2.py` to `scan5.py`. `any_scan-*.txt` holds the qualifier counts. `eqver.txt` holds the equal-version check.
  - `indexes/`: the SHA256 of every index file scanned, and the `Release` files for bookworm, trixie and sid.
    The indexes were downloaded on 2026-11-02 (bookworm, trixie, sid) and 2026-11-06 (wheezy to bullseye).
    The download URLs were not recorded.
    bookworm, trixie and sid change over time, so a later download will differ.
- `sid-history/`: every state of sid from 2012-01-01 to 2026-11-06, rebuilt from snapshot.debian.org.
  - `COVERAGE.txt`: what was covered, how it was verified, and the anomalies found.
  - `scripts/`:
    - `run.py` drives the scan (`run_v1.py` is the first version).
    - `scanstate.py` holds the checks C1–C7.
    - `pdiff.py` applies Debian's `Packages.diff` patches.
    - `debver.py` is dpkg's version comparison.
    - `indep.py` is the independent line grep.
    - `fill2.py` and `merge.py` handle the states between snapshots.
    - `vtest/` tests `debver.py` against dpkg's own `verrevcmp`, from `vc.c`, on random pairs.
  - `results/final-all-states/`: the final run.
    - `occurrences.txt` holds the findings.
    - `coverage_summary.txt` and `coverage.tsv` hold coverage per stream and per state.
    - `intermediate.tsv` lists the states between snapshots.
    - `any_atoms.tsv` and `explicit_qual_neg_atoms.tsv` list every qualified negative atom seen.
  - `results/pass1-snapshot-states/`: the first, online pass over snapshot states only. It found the same things.
  - `results/independent-line-grep.txt`: a grep of every downloaded file and patch, which agrees with C1 and C4.

The raw downloads for the sid history are not here: 6.8 GB, kept on iphito at `/mnt/disk3/ryan/snapshot-scan/data/`.
They can be fetched again from snapshot.debian.org, and every rebuilt file was checked against the SHA256 that the archive published for it.

## Checks C1–C7 (sid history)

- **C1:** a `Provides` entry with an architecture qualifier.
- **C2:** a `:any` atom in Conflicts or Breaks matching, by name and version, a real package that is not `Multi-Arch: allowed`.
- **C3:** an explicitly qualified atom in Conflicts or Breaks whose name has a provider at a different architecture.
- **C4:** a `:all` qualifier in any relation field.
- **C5:** a `:native` qualifier in any relation field.
- **C6:** two distinct version strings of a name, in one architecture index, that compare equal; or the same version string twice at one architecture.
- **C7:** a duplicate field, a field-name case other than the usual one, a `|` in Conflicts/Breaks/Provides, or a stanza without `Architecture`.

## Reproducing

The scripts are plain Python 3 with no dependencies; run them with `python3 -I`.
Each script's docstring gives its usage.
The release-head scripts take directories of downloaded `Packages` files.
The sid-history scan fetches from snapshot.debian.org with a delay between requests, keeps every download, and can replay offline from that cache.
