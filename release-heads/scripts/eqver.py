"""Find distinct version strings of one name at one architecture that
compare equal under dpkg's ordering, per release and architecture index.
An Architecture: all stanza is filed at the index's architecture, as
pac files it at the native one.

Usage: python3 -I eqver.py DEBVER_DIR FILE...
Each FILE is named .../<release>/<comp>-<arch>.Packages.xz or
.../<release>-<comp>-<arch>.xz.
"""
import gzip
import lzma
import sys
from collections import defaultdict
from functools import cmp_to_key
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from debver import vcmp  # noqa: E402


def key_of(p):
    if p.name.endswith(".Packages.xz"):
        comp, arch = p.name[: -len(".Packages.xz")].rsplit("-", 1)
        return p.parent.name, arch, comp
    rel, rest = p.stem.split("-", 1)
    comp, arch = rest.rsplit("-", 1)
    return rel, arch, comp


def stanzas(p):
    cur = {}
    op = gzip.open if p.suffix == ".gz" else lzma.open
    with op(p, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip() == "":
                if cur:
                    yield cur
                cur = {}
            elif not line[0].isspace() and ":" in line:
                k, v = line.split(":", 1)
                cur[k.strip().lower()] = v.strip()
    if cur:
        yield cur


groups = defaultdict(lambda: defaultdict(set))  # (rel, arch) -> (name, effarch) -> versions
counts = defaultdict(int)
for f in sys.argv[2:]:
    p = Path(f)
    rel, arch, comp = key_of(p)
    for s in stanzas(p):
        a = s.get("architecture", "")
        eff = arch if a == "all" else a
        groups[(rel, arch)][(s.get("package"), eff)].add(s.get("version"))
        counts[(rel, arch)] += 1

hits = 0
for (rel, arch), g in sorted(groups.items()):
    found = []
    for (name, eff), vs in g.items():
        vs = sorted(vs, key=cmp_to_key(vcmp))
        for i in range(len(vs) - 1):
            if vcmp(vs[i], vs[i + 1]) == 0:
                found.append(f"{name}:{eff} {vs[i]!r} == {vs[i + 1]!r}")
    hits += len(found)
    print(f"{rel} {arch}: {counts[(rel, arch)]} stanzas, {len(found)} equal pairs")
    for x in found:
        print("   ", x)
print("total equal pairs:", hits)
