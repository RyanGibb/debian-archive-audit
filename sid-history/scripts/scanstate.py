"""Incremental state of all sid binary Packages files and checks C1..C7.

Files are keyed (comp, idxarch).  Each file is a Counter of stanza byte
strings.  Per-stanza checks run once per distinct stanza text; relational
checks (C2, C3, C6) are re-evaluated whenever either side changes.
"""
import functools
from collections import Counter, defaultdict

from debver import parse_field, sat, vcmp

REL = ["Pre-Depends", "Depends", "Recommends", "Suggests", "Enhances",
       "Conflicts", "Breaks", "Provides", "Replaces"]
REL_LC = {f.lower(): f for f in REL}
CANON = ["Package", "Version", "Architecture", "Multi-Arch"] + REL
CANON_LC = {f.lower(): f for f in CANON}
NEG = ("Conflicts", "Breaks")
SPECIAL_Q = ("any", "native", "all")


def split_stanzas(data):
    return [s for s in data.split(b"\n\n") if s.strip(b"\n")]


class Info:
    __slots__ = ("pkg", "ver", "arch", "ma", "findings", "anyneg", "qualneg",
                 "provides", "anycount", "fields")


def parse_stanza(sb):
    text = sb.decode("utf-8", "replace").strip("\n")
    fields = []  # (name, value)
    bad_lines = []
    for line in text.split("\n"):
        if not line:
            continue
        if line[0] in " \t":
            if fields:
                k, v = fields[-1]
                fields[-1] = (k, v + "\n" + line.strip())
            else:
                bad_lines.append(line)
            continue
        if ":" not in line:
            bad_lines.append(line)
            continue
        k, _, v = line.partition(":")
        fields.append((k, v.strip()))
    info = Info()
    first = {}
    for k, v in fields:
        first.setdefault(k.lower(), v)
    info.pkg = first.get("package", "")
    info.ver = first.get("version", "")
    info.arch = first.get("architecture")
    info.ma = first.get("multi-arch")
    F = []  # (check, detail)
    for line in bad_lines:
        F.append(("C7-line-without-field", line[:200]))
    names = Counter(k.lower() for k, _ in fields)
    for kl, n in names.items():
        if n > 1:
            texts = "; ".join(f"{k}: {v}" for k, v in fields if k.lower() == kl)
            F.append(("C7-duplicate-field", texts))
    for k, v in fields:
        kl = k.lower()
        if kl in CANON_LC and k != CANON_LC[kl]:
            F.append(("C7-noncanonical-case", f"{k}: {v}"))
        if k != k.strip():
            F.append(("C7-field-name-whitespace", f"{k!r}: {v}"))
    if info.arch is None:
        F.append(("C7-no-architecture", ""))
    info.anyneg = []
    info.qualneg = []
    info.provides = []
    info.anycount = []
    for k, v in fields:
        field = REL_LC.get(k.lower())
        if field is None:
            continue
        ftext = f"{k}: {v}"
        if field in ("Conflicts", "Breaks", "Provides") and "|" in v:
            F.append(("C7-alternative-in-" + field, ftext))
        for cl in parse_field(v):
            if cl is None:
                continue
            for raw, g in cl:
                if g is None:
                    F.append(("X-unparsed-atom", f"{ftext}  [atom {raw!r}]"))
                    continue
                q = g["qual"]
                if field == "Provides":
                    info.provides.append((g["name"], g["op"], g["ver"] if g["op"] is not None else None))
                    if q:
                        F.append(("C1-provides-qualified", f"{ftext}  [atom {raw}]"))
                if q == "all":
                    F.append(("C4-qual-all", f"{ftext}  [atom {raw}]"))
                if q == "native":
                    F.append(("C5-qual-native", f"{ftext}  [atom {raw}]"))
                if q == "any" and field in ("Conflicts", "Breaks", "Replaces"):
                    info.anycount.append((field, raw))
                if field in NEG and q == "any":
                    info.anyneg.append((field, ftext, raw, g["name"], g["op"], g["ver"]))
                if field in NEG and q and q not in SPECIAL_Q:
                    info.qualneg.append((field, ftext, raw, g["name"], q, g["op"], g["ver"]))
                if q and q not in SPECIAL_Q and field not in NEG:
                    pass
    info.findings = F
    return info


def _vkey(v):
    return functools.cmp_to_key(vcmp)(v)


class Occ:
    """Occurrence registry: key -> [first_ts, last_ts, n_states, extra(set)]."""

    def __init__(self):
        self.d = {}

    def hit(self, key, ts, extra=None):
        r = self.d.get(key)
        if r is None:
            r = self.d[key] = [ts, ts, 0, set(), None]
        if r[4] != ts:
            r[1] = ts
            r[2] += 1
            r[4] = ts
        if extra is not None:
            r[3].add(extra)


class State:
    def __init__(self):
        self.files = {}               # (comp, arch) -> Counter[stanza bytes]
        self.info = {}                # stanza bytes -> Info
        self.refs = Counter()         # stanza bytes -> total count across files
        self.real = defaultdict(Counter)    # name -> Counter[(comp, idx, Arch, Ver, MA)]
        self.provs = defaultdict(Counter)   # name -> Counter[(comp, idx, Pkg, Arch, Ver, op, pver)]
        self.anyneg = Counter()       # (comp, idx, sb)
        self.qualneg = Counter()
        self.flagged = Counter()      # (comp, idx, sb) with per-stanza findings
        self.pv = defaultdict(Counter)      # (idx, Pkg) -> Counter[(Ver, Arch, comp)]
        self.dirty_pv = set()
        self.dirty_names = set()
        self.new_neg = set()
        self.occ = Occ()
        self.any_atoms = set()        # (field, comp, idx, Pkg, Ver, Arch, raw)
        self.qual_atoms_with_provider = set()
        self.qual_atoms_all = set()
        self.c2_active = {}           # (comp, idx, sb, i) -> matches tuple
        self.c3_active = {}
        self.c6_active = {}           # (idx, Pkg) -> list of (kind, detail)
        self.stanzas_scanned = 0

    def _info(self, sb):
        inf = self.info.get(sb)
        if inf is None:
            inf = self.info[sb] = parse_stanza(sb)
            self.stanzas_scanned += 1
        return inf

    def _adjust(self, comp, idx, sb, inf, delta):
        a = inf.arch if inf.arch is not None else "<none>"
        ma = inf.ma or "no"
        self.real[inf.pkg][(comp, idx, a, inf.ver, ma)] += delta
        self.dirty_names.add(inf.pkg)
        for (n, op, pv) in inf.provides:
            self.provs[n][(comp, idx, inf.pkg, a, inf.ver, op, pv)] += delta
            self.dirty_names.add(n)
        key = (comp, idx, sb)
        if inf.anyneg:
            self.anyneg[key] += delta
        if inf.qualneg:
            self.qualneg[key] += delta
        if inf.anyneg or inf.qualneg:
            if delta > 0:
                self.new_neg.add(key)
        if inf.findings:
            self.flagged[key] += delta
        self.pv[(idx, inf.pkg)][(inf.ver, a, comp)] += delta
        self.dirty_pv.add((idx, inf.pkg))
        self.refs[sb] += delta
        if self.refs[sb] <= 0:
            del self.refs[sb]
            self.info.pop(sb, None)

    def set_file(self, comp, idx, stanzas):
        """Replace a file's content (list of stanza bytes, or None = absent)."""
        new = Counter(stanzas) if stanzas is not None else Counter()
        old = self.files.get((comp, idx), Counter())
        added = new - old
        removed = old - new
        for sb, n in removed.items():
            inf = self.info[sb]
            self._adjust(comp, idx, sb, inf, -n)
        for sb, n in added.items():
            inf = self._info(sb)
            self._adjust(comp, idx, sb, inf, n)
            if inf.anycount:
                a = inf.arch or "<none>"
                for field, raw in inf.anycount:
                    self.any_atoms.add((field, comp, idx, inf.pkg, inf.ver, a, raw))
        if stanzas is None:
            self.files.pop((comp, idx), None)
        else:
            self.files[(comp, idx)] = new
        return len(added), len(removed)

    @staticmethod
    def _clean(c):
        for k in [k for k, v in c.items() if v <= 0]:
            del c[k]

    def evaluate(self, ts):
        occ = self.occ
        self._clean(self.anyneg)
        self._clean(self.qualneg)
        self._clean(self.flagged)
        dn = self.dirty_names
        for n in dn:
            self._clean(self.real[n])
            self._clean(self.provs[n])
        # per-stanza findings
        for (comp, idx, sb) in self.flagged:
            inf = self.info[sb]
            for chk, detail in inf.findings:
                occ.hit((chk, comp, idx, inf.pkg, inf.ver, inf.arch, detail), ts)
        # C2
        for k in [k for k in self.c2_active if k[:3] not in self.anyneg]:
            del self.c2_active[k]
        for key in self.anyneg:
            comp, idx, sb = key
            inf = self.info[sb]
            for i, (field, ftext, raw, n, op, ver) in enumerate(inf.anyneg):
                ak = key + (i,)
                if key in self.new_neg or n in dn or ak not in self.c2_active:
                    m = tuple(sorted(
                        (c, ix, a, v, ma) for (c, ix, a, v, ma) in self.real.get(n, ())
                        if ma != "allowed" and sat(v, op, ver)))
                    self.c2_active[ak] = m
                m = self.c2_active[ak]
                if m:
                    self_hit = all(x[3] == inf.ver and n == inf.pkg for x in m)
                    occ.hit(("C2-any-neg-on-non-allowed", comp, idx, inf.pkg, inf.ver, inf.arch,
                             f"{ftext}  [atom {raw}]"), ts,
                            ("self-only " if self_hit else "") + "; ".join(
                                f"{a}/{v}/MA={ma}@{c}/{ix}" for (c, ix, a, v, ma) in m[:6])
                            + (f" (+{len(m) - 6})" if len(m) > 6 else ""))
        # C3
        for k in [k for k in self.c3_active if k[:3] not in self.qualneg]:
            del self.c3_active[k]
        for key in self.qualneg:
            comp, idx, sb = key
            inf = self.info[sb]
            for i, (field, ftext, raw, n, q, op, ver) in enumerate(inf.qualneg):
                ak = key + (i,)
                if key in self.new_neg or n in dn or ak not in self.c3_active:
                    prov = list(self.provs.get(n, ()))
                    m = tuple(sorted(
                        (c, ix, p, a, v, pop, pv) for (c, ix, p, a, v, pop, pv) in prov
                        if a != q and (op is None or (pop == "=" and sat(pv, op, ver)))))
                    self.c3_active[ak] = (bool(prov), m)
                    self.qual_atoms_all.add((field, comp, idx, inf.pkg, inf.ver, inf.arch, raw))
                    if prov:
                        self.qual_atoms_with_provider.add((field, comp, idx, inf.pkg, inf.ver, inf.arch, raw))
                hasprov, m = self.c3_active[ak]
                if m:
                    occ.hit(("C3-qualified-neg-vs-foreign-provider", comp, idx, inf.pkg, inf.ver, inf.arch,
                             f"{ftext}  [atom {raw}]"), ts,
                            "; ".join(f"{p}/{a}/{v} provides {n}" + (f" (= {pv})" if pop else "")
                                      + f"@{c}/{ix}" for (c, ix, p, a, v, pop, pv) in m[:6])
                            + (f" (+{len(m) - 6})" if len(m) > 6 else ""))
        # C6
        for k in self.dirty_pv:
            c = self.pv.get(k)
            if c is not None:
                self._clean(c)
            res = []
            if c:
                byva = Counter()
                for (v, a, comp), cnt in c.items():
                    byva[(v, a)] += cnt
                for (v, a), cnt in byva.items():
                    if cnt > 1:
                        comps = sorted(f"{cc}x{n}" for (vv, aa, cc), n in c.items() if vv == v and aa == a)
                        res.append(("C6-identical-version-string", f"Architecture={a} Version={v} in {','.join(comps)}"))
                vs = sorted({v for (v, a, comp) in c}, key=_vkey)
                for i in range(len(vs) - 1):
                    if vcmp(vs[i], vs[i + 1]) == 0:
                        locs = sorted(f"{v}/{a}@{cc}" for (v, a, cc) in c if v in (vs[i], vs[i + 1]))
                        res.append(("C6-equal-distinct-versions", f"{vs[i]!r} == {vs[i + 1]!r}: {', '.join(locs)}"))
            if res:
                self.c6_active[k] = res
            else:
                self.c6_active.pop(k, None)
                if c is not None and not c:
                    del self.pv[k]
        for (idx, pkg), res in self.c6_active.items():
            for chk, detail in res:
                occ.hit((chk, "*", idx, pkg, "*", "*", detail), ts)
        self.dirty_pv = set()
        self.dirty_names = set()
        self.new_neg = set()
