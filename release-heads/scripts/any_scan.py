"""Scan Debian Packages.xz indices for arch-qualified relation names.

Usage: python3 -I any_scan.py DATA_DIR SUITE [SUITE ...]
Expects DATA_DIR/SUITE/<component>-<arch>.Packages.xz.
"""
import lzma
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

NEG = ("Breaks", "Conflicts", "Replaces")
POS = ("Depends", "Pre-Depends", "Recommends", "Suggests", "Enhances")
ALL_REL = NEG + POS + ("Provides",)

RESTRICT = re.compile(r"\[[^\]]*\]|<[^>]*>|\([^)]*\)")


def stanzas(path):
    with lzma.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        cur, key = {}, None
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                if cur:
                    yield cur
                cur, key = {}, None
            elif line[0] in " \t":
                if key:
                    cur[key] += " " + line.strip()
            else:
                k, _, v = line.partition(":")
                key = k
                cur[k] = v.strip()
        if cur:
            yield cur


def relations(text):
    """Yield (raw_alternative, bare_name_with_qualifier)."""
    for clause in text.split(","):
        for alt in clause.split("|"):
            alt = alt.strip()
            if not alt:
                continue
            name = RESTRICT.sub("", alt).strip().split()[0] if RESTRICT.sub("", alt).strip() else ""
            yield alt, name


def main():
    data = Path(sys.argv[1])
    suites = sys.argv[2:]
    for suite in suites:
        any_counts = Counter()       # field -> count of :any alternatives
        any_counts_uniq = defaultdict(set)  # field -> {(pkg, ver, arch)}
        other_qual = Counter()       # (field, qualifier) -> count
        hits = []                    # neg :any hits
        index_by_arch = defaultdict(lambda: {"named": defaultdict(list), "prov": defaultdict(list)})
        seen = set()
        files = sorted((data / suite).glob("*.Packages.xz"))
        for f in files:
            comp, idx_arch = f.name[: -len(".Packages.xz")].rsplit("-", 1)
            idx = index_by_arch[idx_arch]
            for st in stanzas(f):
                pkg, ver, arch = st.get("Package"), st.get("Version"), st.get("Architecture")
                ma = st.get("Multi-Arch", "no") or "no"
                rec = (pkg, ver, arch, ma, comp)
                idx["named"][pkg].append(rec)
                for _, pname in relations(st.get("Provides", "")):
                    idx["prov"][pname.split(":")[0]].append(rec + (pname,))
                # count each binary stanza once even if arch:all repeats per index
                ident = (pkg, ver, arch)
                first = ident not in seen
                seen.add(ident)
                for field in ALL_REL:
                    if field not in st:
                        continue
                    for alt, name in relations(st[field]):
                        if ":" not in name:
                            continue
                        qual = name.split(":", 1)[1]
                        if first:
                            if qual == "any":
                                any_counts[field] += 1
                                any_counts_uniq[field].add(ident)
                            else:
                                other_qual[(field, qual)] += 1
                        if qual == "any" and field in NEG:
                            hits.append((idx_arch, comp, pkg, ver, arch, ma, field, st[field], alt, name))

        print(f"===== {suite}  ({len(files)} indices)")
        print("  :any alternative counts (unique binary stanzas, arch:all counted once):")
        for field in ALL_REL:
            print(f"    {field:12s} {any_counts[field]:6d} alternatives in {len(any_counts_uniq[field]):6d} stanzas")
        print("  other qualifiers:")
        for (field, q), n in sorted(other_qual.items()):
            print(f"    {field:12s} :{q:10s} {n}")
        print(f"  :any Breaks/Conflicts/Replaces hits (per index arch): {len(hits)}")
        for (idx_arch, comp, pkg, ver, arch, ma, field, full, alt, name) in hits:
            target = name.split(":")[0]
            idx = index_by_arch[idx_arch]
            named = idx["named"].get(target, [])
            prov = idx["prov"].get(target, [])
            classes = [r[3] for r in named] + [r[3] for r in prov]
            if not classes:
                flag = "NO-TARGET"
            elif all(c == "allowed" for c in classes):
                flag = "consistent"
            else:
                flag = "DIVERGENT"
            print(f"  -- [{idx_arch}] {comp} {pkg} {ver} arch={arch} M-A={ma}")
            print(f"     {field}: {full}")
            print(f"     relation: {alt}   target: {target}   => {flag}")
            for r in named:
                print(f"       named   : {r[0]} {r[1]} arch={r[2]} M-A={r[3]} ({r[4]})")
            for r in prov:
                print(f"       provider: {r[0]} {r[1]} arch={r[2]} M-A={r[3]} ({r[4]}) Provides {r[5]}")


if __name__ == "__main__":
    main()
