"""Audit scan of Debian Packages indexes for features the model may omit.

Usage: python3 -I scan.py ANY_DIR PROV_DIR OUT_DIR
"""
import gzip
import lzma
import re
import sys
import json
from collections import Counter, defaultdict
from pathlib import Path

REL = ["Pre-Depends", "Depends", "Recommends", "Suggests", "Enhances",
       "Conflicts", "Breaks", "Provides", "Replaces"]
REL_LC = {f.lower(): f for f in REL}
CANON = ["Package", "Version", "Architecture", "Multi-Arch", "Essential",
         "Protected", "Important", "Priority", "Source"] + REL
CANON_LC = {f.lower(): f for f in CANON}
OBSOLETE = {"recommended", "optional", "revision", "class"}

ALT = re.compile(
    r"^\s*(?P<name>[^\s:(\[<|,]+)(?::(?P<qual>[^\s(\[<|,]+))?\s*"
    r"(?:\(\s*(?P<op><<|<=|>=|>>|=|<|>|)\s*(?P<ver>[^)\s]*)\s*\))?\s*"
    r"(?P<arch>\[[^\]]*\])?\s*(?P<prof>(?:<[^>]*>\s*)*)$")


def opener(p):
    if p.suffix == ".gz":
        return gzip.open(p, "rt", encoding="utf-8", errors="replace")
    return lzma.open(p, "rt", encoding="utf-8", errors="replace")


def stanzas(path):
    with opener(path) as fh:
        cur, key = [], None
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                if cur:
                    yield cur
                cur = []
            elif line[0] in " \t":
                if cur:
                    k, v = cur[-1]
                    cur[-1] = (k, v + "\n" + line.strip())
            else:
                k, _, v = line.partition(":")
                cur.append((k, v.strip()))
        if cur:
            yield cur


# dpkg verrevcmp
def order(c):
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    if c:
        return ord(c) + 256
    return 0


def verrevcmp(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = order(a[i]) if i < len(a) else 0
            bc = order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def split_ver(v):
    e = 0
    if ":" in v:
        ep, rest = v.split(":", 1)
        if ep.isdigit():
            e, v = int(ep), rest
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, ""
    return e, up, rev


def vcmp(a, b):
    ea, ua, ra = split_ver(a)
    eb, ub, rb = split_ver(b)
    if ea != eb:
        return ea - eb
    c = verrevcmp(ua, ub)
    if c:
        return c
    return verrevcmp(ra, rb)


def sat(v, op, w):
    if op is None:
        return True
    c = vcmp(v, w)
    return {"<<": c < 0, "<=": c <= 0, "<": c <= 0, "=": c == 0,
            ">=": c >= 0, ">": c >= 0, ">>": c > 0, "": c == 0}[op]


def parse_field(text):
    clauses = []
    for clause in text.split(","):
        if not clause.strip():
            clauses.append(None)
            continue
        alts = []
        for alt in clause.split("|"):
            m = ALT.match(alt)
            alts.append((alt.strip(), m.groupdict() if m else None))
        clauses.append(alts)
    return clauses


def releases(any_dir, prov_dir):
    rel = defaultdict(list)
    for d in sorted(Path(any_dir).iterdir()):
        if d.is_dir():
            for f in sorted(d.glob("*.Packages.xz")):
                comp, arch = f.name[: -len(".Packages.xz")].rsplit("-", 1)
                rel[d.name].append((comp, arch, f))
    for f in sorted(Path(prov_dir).iterdir()):
        stem = f.name.rsplit(".", 1)[0]
        r, comp, arch = stem.split("-", 1)[0], stem.split("-", 1)[1].rsplit("-", 1)[0], stem.rsplit("-", 1)[1]
        rel[r].append((comp, arch, f))
    return rel


def main():
    any_dir, prov_dir, out_dir = sys.argv[1:4]
    out = Path(out_dir)
    out.mkdir(exist_ok=True)
    only = sys.argv[4:] or None
    summary = {}
    for r, files in releases(any_dir, prov_dir).items():
        if only and r not in only:
            continue
        C = Counter()
        EX = defaultdict(list)

        def ex(k, s):
            C[k] += 1
            if len(EX[k]) < 4:
                EX[k].append(s)

        archs = sorted({a for _, a, _ in files})
        # (pkg, arch) -> list of (version, comp, relsig)
        byKey = defaultdict(list)
        provided_by = defaultdict(set)   # name -> {(pkg, arch, ver)}
        real = defaultdict(set)          # name -> {(arch, ver)}
        essential = {}                   # (name, arch) -> versions
        negs = []                        # (pkg, arch, ver, field, alt dict, raw)
        seen_all = set()
        for comp, arch, f in files:
            for st in stanzas(f):
                d = {}
                names = Counter(k for k, _ in st)
                for k, n in names.items():
                    if n > 1:
                        ex("dup_field:" + k, f"{f.name}")
                for k, v in st:
                    kl = k.lower()
                    if kl in CANON_LC and k != CANON_LC[kl]:
                        ex("noncanon_case:" + k, f"{f.name} {dict(st).get('Package')}")
                    if kl in OBSOLETE:
                        ex("obsolete_field:" + k, f"{f.name} {dict(st).get('Package')}")
                    d.setdefault(k, v)
                pkg = d.get("Package", "")
                ver = d.get("Version", "")
                a = d.get("Architecture")
                if a is None:
                    ex("missing_arch", f"{f.name} {pkg}")
                    a = "<none>"
                if a != "all" and a != arch and a != "<none>":
                    ex("arch_mismatch_index", f"{f.name} {pkg} {a}")
                key_arch = a
                ident = (pkg, key_arch, ver, comp)
                if a == "all":
                    if ident in seen_all:
                        continue
                    seen_all.add(ident)
                C["stanzas"] += 1
                if pkg != pkg.lower():
                    ex("upper_pkg", f"{f.name} {pkg} {ver}")
                ma = d.get("Multi-Arch")
                if ma is not None:
                    C["ma:" + ma] += 1
                    if ma not in ("no", "same", "foreign", "allowed"):
                        ex("ma_unknown:" + ma, f"{pkg} {ver} {a}")
                    if ma == "same" and a == "all":
                        ex("ma_same_arch_all", f"{f.name} {pkg} {ver}")
                    if ma == "no":
                        ex("ma_explicit_no", f"{pkg} {ver} {a}")
                for flag in ("Essential", "Protected", "Important"):
                    if flag in d:
                        C[f"{flag}:{d[flag]}"] += 1
                if d.get("Essential") == "yes":
                    essential.setdefault((pkg, a), set()).add(ver)
                sig = tuple(d.get(k, "") for k in REL) + (ma or "",)
                byKey[(pkg, a)].append((ver, comp, sig))
                real[pkg].add((a, ver))
                for field in REL:
                    if field not in d:
                        continue
                    for cl in parse_field(d[field]):
                        if cl is None:
                            ex("empty_clause:" + field, f"{pkg} {ver}")
                            continue
                        if len(cl) > 1 and field in ("Conflicts", "Breaks", "Provides", "Replaces"):
                            ex("alt_in:" + field, f"{pkg} {ver}: {d[field]}")
                        for raw, g in cl:
                            if g is None:
                                ex("unparsed:" + field, f"{pkg} {ver}: {raw!r}")
                                continue
                            n = g["name"]
                            if n != n.lower():
                                ex("upper_relname:" + field, f"{pkg} {ver}: {raw}")
                            if g["op"] is not None:
                                if g["op"] in ("<", ">"):
                                    ex(f"op_{g['op']}:" + field, f"{pkg} {ver}: {raw}")
                                if g["op"] == "":
                                    ex("op_implicit:" + field, f"{pkg} {ver}: {raw}")
                                if field == "Provides" and g["op"] not in ("=",):
                                    ex("prov_nonEq", f"{pkg} {ver}: {raw}")
                            if g["arch"]:
                                ex("archrestr:" + field, f"{pkg} {ver}: {raw}")
                            if g["prof"]:
                                ex("profile:" + field, f"{pkg} {ver}: {raw}")
                            q = g["qual"]
                            if q:
                                kind = q if q in ("any", "native", "all") else "explicit"
                                C[f"qual:{field}:{kind}"] += 1
                                if kind == "explicit" and q not in archs:
                                    ex(f"qual_unconf:{field}:{q}", f"{pkg} {ver} {a}: {raw}")
                            if field == "Provides":
                                provided_by[n].add((pkg, a, ver, g["ver"] if g["op"] == "=" else None, ma or "no"))
                            if field in ("Conflicts", "Breaks"):
                                negs.append((pkg, a, ver, ma or "no", field, g, raw))
        # self conflicts
        prov_of = defaultdict(set)
        for n, ps in provided_by.items():
            for (p, a, v, pv, ma) in ps:
                prov_of[(p, a, v)].add(n)
        for (pkg, a, ver, ma, field, g, raw) in negs:
            n = g["name"]
            if n == pkg:
                ex("self_conflict_name:" + field, f"{pkg} {ver} {a}: {raw}")
            elif n in prov_of[(pkg, a, ver)]:
                ex("self_conflict_virtual:" + field, f"{pkg} {ver} {a}: {raw}")
            if g["qual"] and g["qual"] not in ("any",) and n in provided_by:
                provs = sorted({(p, pa) for (p, pa, v, pv, pm) in provided_by[n]})
                ex("qualneg_on_virtual:" + field, f"{pkg} {ver} {a}: {raw} provided by {provs[:4]}")
            if g["qual"] == "any" and n in provided_by:
                ex("anyneg_on_virtual:" + field, f"{pkg} {ver} {a}: {raw}")
        ess_names = defaultdict(list)
        for (n, a), vs in essential.items():
            for v in vs:
                ess_names[n].append((a, v))
        C["essential_stanzas"] = sum(len(v) for v in essential.values())
        for (pkg, a, ver, ma, field, g, raw) in negs:
            n = g["name"]
            if n == pkg:
                continue
            hit = False
            for (ea, ev) in ess_names.get(n, []):
                if g["qual"] and g["qual"] not in ("any",) and g["qual"] != ea:
                    continue
                if sat(ev, g["op"], g["ver"]) if g["op"] is not None else True:
                    hit = True
            if hit:
                ex("neg_on_essential:" + field, f"{pkg} {ver} {a}: {raw}")
        # duplicates (pkg, arch, version) with different relation fields; equal-but-distinct versions
        for (pkg, a), lst in byKey.items():
            byv = defaultdict(set)
            for (v, comp, sig) in lst:
                byv[v].add(sig)
            for v, sigs in byv.items():
                if len(sigs) > 1:
                    ex("dup_version_diff_rel", f"{pkg} {a} {v} comps={[c for (vv, c, s) in lst if vv == v]}")
                if sum(1 for (vv, c, s) in lst if vv == v) > 1:
                    C["dup_version_any"] += 1
            vs = sorted(byv)
            for i in range(len(vs)):
                for j in range(i + 1, len(vs)):
                    if vcmp(vs[i], vs[j]) == 0:
                        ex("equal_distinct_versions", f"{pkg} {a} {vs[i]!r} {vs[j]!r}")
            if len(byv) > 1:
                C["multi_version_keys"] += 1
        summary[r] = {"counts": dict(sorted(C.items())), "examples": {k: v for k, v in sorted(EX.items())}}
        (out / f"{r}.json").write_text(json.dumps(summary[r], indent=1))
        print(f"== {r}: {C['stanzas']} stanzas", flush=True)


main()
