"""Recover dinstall states hidden behind snapshots whose Release and pdiff Index
disagree (the snapshot caught the mirror mid-update), by chaining the Index's
own patches up to the Index's SHA256-Current.

Usage: python3 -I fill2.py SCRIPTS DATA OUT PREV_TS INDEX_TS
  PREV_TS: last good snapshot before the hole (all streams seeded there)
  INDEX_TS: snapshot whose Packages.diff/Index (and patches) are used
"""
import re
import sys

scripts, data, out, prev_ts, idx_ts = sys.argv[1:6]
sys.argv = [sys.argv[0], scripts, data, out, "--intermediate"]
sys.path.insert(0, scripts)
import run  # noqa: E402
from scanstate import State, split_stanzas  # noqa: E402

state = State()
rel = run.get(prev_ts, "dists/sid/Release")
fields, sums = run.parse_release(rel.decode("utf-8", "replace"))
files = sums["SHA256"]
streams = {}
for c in run.COMPS:
    for a in run.ARCHS:
        key = f"{c}/binary-{a}/Packages"
        if key not in files:
            continue
        st = run.Stream(c, a)
        d, ext = run.seed(st, prev_ts, files)
        st.set_content(d)
        assert st.sha256 == files[key][0], key
        state.set_file(c, a, split_stanzas(d))
        streams[(c, a)] = st
state.evaluate(prev_ts)
byname = {}
final = {}
for (c, a), st in streams.items():
    idx = run.load_index(idx_ts, st)
    if idx is None:
        continue
    targets = {idx["alg"]: idx["cur"]}
    st.look = idx
    if st.ours(idx["alg"]) == idx["cur"]:
        continue
    p = run.plan(idx, st, targets)
    if p is None:
        print(f"{c}/{a}: no plan", flush=True)
        continue
    dat, n, inters = run.try_pdiff(st, idx_ts, [idx_ts], 0, targets)
    if dat is None:
        print(f"{c}/{a}: pdiff failed", flush=True)
        continue
    st.set_content(dat)
    ok = st.ours(idx["alg"]) == idx["cur"]
    print(f"{c}/{a}: {n} patches, final verified={ok}, intermediates verified="
          f"{sum(v for _, _, v in inters)}/{len(inters)}", flush=True)
    for pname, ls, ver in inters:
        byname.setdefault(pname, []).append((c, a, b"".join(ls), ver))
    last = p[-1][4]
    byname.setdefault(last, []).append((c, a, dat, ok))


def label(pname):
    m = re.match(r"^(\d{4})-(\d\d)-(\d\d)-(\d\d)(\d\d)\.(\d\d)$", pname)
    return "".join(m.groups()[:3]) + "T" + "".join(m.groups()[3:]) + "D"


for pname in sorted(byname):
    for c, a, d, ver in byname[pname]:
        state.set_file(c, a, split_stanzas(d))
    state.evaluate(label(pname))
    print(label(pname), ",".join(f"{c}/{a}{'' if v else '!'}" for c, a, _, v in byname[pname]), flush=True)
print("occurrences:", {k: (v[0], v[1]) for k, v in state.occ.d.items()})
print("any_atoms", len(state.any_atoms), "qual_with_provider", len(state.qual_atoms_with_provider))
