"""Fourth pass, per release and per architecture (that arch's index plus its
arch:all stanzas, as a single-arch view):
- Pre-Depends cycles: SCCs (size >= 2) of the name graph p -> q where p
  Pre-Depends on an atom naming n and q is n or provides n; 'forced' SCCs are
  those whose cycle edges all come from one-alternative clauses
- Conflicts/Breaks atoms matched by an Essential: yes or Protected: yes
  package (real name or provider, version formula checked), declarer excluded
- qualifiers ':all' and ':native' on any relation field

Usage: python3 -I scan4.py ANY_DIR PROV_DIR [SUITE ...]
"""
import sys
from collections import defaultdict, Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scan_lib import stanzas, releases, parse_field, sat  # noqa: E402

REL = ["Pre-Depends", "Depends", "Recommends", "Suggests", "Enhances",
       "Conflicts", "Breaks", "Provides", "Replaces"]


def atoms(text):
    for cl in parse_field(text or ""):
        if cl is None:
            continue
        yield [g for raw, g in cl if g]


def sccs(nodes, edges):
    index, low, onstack, stack, out = {}, {}, set(), [], []
    counter = [0]
    for root in nodes:
        if root in index:
            continue
        work = [(root, iter(edges.get(root, ())))]
        index[root] = low[root] = counter[0]; counter[0] += 1
        stack.append(root); onstack.add(root)
        while work:
            v, it = work[-1]
            pushed = False
            for w in it:
                if w not in index:
                    index[w] = low[w] = counter[0]; counter[0] += 1
                    stack.append(w); onstack.add(w)
                    work.append((w, iter(edges.get(w, ()))))
                    pushed = True
                    break
                elif w in onstack:
                    low[v] = min(low[v], index[w])
            if pushed:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[v])
            if low[v] == index[v]:
                comp = []
                while True:
                    w = stack.pop(); onstack.discard(w); comp.append(w)
                    if w == v:
                        break
                if len(comp) > 1:
                    out.append(comp)
    return out


def main():
    any_dir, prov_dir = sys.argv[1:3]
    only = sys.argv[3:] or None
    for r, files in releases(any_dir, prov_dir).items():
        if only and r not in only:
            continue
        quals = Counter()
        for arch in sorted({a for _, a, _ in files}):
            sts = [dict(st) for comp, a, f in files if a == arch for st in stanzas(f)]
            provs = defaultdict(list)  # name -> [(pkg, ver or None)]
            real = defaultdict(list)   # name -> [ver]
            ess = []
            for d in sts:
                real[d["Package"]].append(d["Version"])
                for alts in atoms(d.get("Provides")):
                    for g in alts:
                        provs[g["name"]].append((d["Package"], g["ver"] if g["op"] == "=" else None))
                if d.get("Essential") == "yes" or d.get("Protected") == "yes":
                    ess.append(d)
                for fld in REL:
                    for alts in atoms(d.get(fld)):
                        for g in alts:
                            if g["qual"] in ("all", "native"):
                                quals[(fld, g["qual"])] += 1
            # Pre-Depends graph
            edges = defaultdict(set)
            forced = defaultdict(set)
            for d in sts:
                p = d["Package"]
                for alts in atoms(d.get("Pre-Depends")):
                    tgts = set()
                    for g in alts:
                        n = g["name"]
                        if n in real:
                            tgts.add(n)
                        tgts.update(q for q, _ in provs.get(n, ()))
                    tgts.discard(p)
                    edges[p] |= tgts
                    if len(alts) == 1 and len(tgts) == 1:
                        forced[p] |= tgts
            comps = sccs(list(edges), edges)
            fcomps = sccs(list(forced), forced)
            # negatives on essential/protected
            ess_names = {}
            for d in ess:
                ess_names.setdefault(d["Package"], []).append((d["Version"], None))
                for alts in atoms(d.get("Provides")):
                    for g in alts:
                        ess_names.setdefault(g["name"], []).append(
                            (g["ver"] if g["op"] == "=" else "", d["Package"]))
            hits = []
            for d in sts:
                for fld in ("Conflicts", "Breaks"):
                    for alts in atoms(d.get(fld)):
                        for g in alts:
                            for v, via in ess_names.get(g["name"], ()):
                                holder = via or g["name"]
                                if holder == d["Package"]:
                                    continue
                                if g["op"] is None:
                                    ok = True
                                elif v == "":
                                    ok = False
                                else:
                                    ok = sat(v, g["op"], g["ver"])
                                if ok:
                                    hits.append(f"{d['Package']} {d['Version']} {fld}: {g['name']}"
                                                f"{' (' + g['op'] + ' ' + g['ver'] + ')' if g['op'] else ''}"
                                                f" hits {holder}")
            print(f"== {r} {arch}: predep SCCs={len(comps)} sizes={sorted(len(c) for c in comps)[:10]} "
                  f"forced={len(fcomps)} {[sorted(c)[:6] for c in fcomps][:3]}; "
                  f"essential/protected stanzas={len(ess)} neg-hits={len(hits)} {sorted(set(hits))[:6]}",
                  flush=True)
            if comps:
                print("   example SCC:", sorted(comps[0])[:8])
        print(f"== {r}: ':all'/':native' qualifiers: {dict(quals)}", flush=True)


main()
