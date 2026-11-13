"""Replay Debian sid binary Packages through every snapshot.debian.org state.

Usage: python3 -I run.py SCRIPTS_DIR DATA_DIR RESULTS_DIR [--from TS] [--to TS] [--limit N]

For each snapshot timestamp: fetch dists/sid/Release, and for each
(component, arch) whose Packages checksum changed, advance the reconstructed
file by pdiffs (Index from a look-ahead snapshot, so that one Index serves
many steps), verifying the result against the Release checksum.  On any
failure, re-seed from the full Packages.{xz,bz2,gz}.
"""
import bz2
import gzip
import hashlib
import json
import lzma
import os
import pickle
import re
import sys
import time

sys.path.insert(0, sys.argv[1])
import fetch  # noqa: E402
from pdiff import PatchError, apply_ed, parse_index  # noqa: E402
from scanstate import State, split_stanzas  # noqa: E402

DATA, RES = sys.argv[2], sys.argv[3]
ARGS = sys.argv[4:]


def arg(name, default=None):
    return ARGS[ARGS.index(name) + 1] if name in ARGS else default


START = arg("--from", "20120101T000000Z")
END = arg("--to", "99999999T999999Z")
LIMIT = int(arg("--limit", "0"))
OFFLINE = "--offline" in ARGS        # only seeds/Release may hit the network
INTER = "--intermediate" in ARGS     # also scan dinstall states between snapshots
OFFLINE_MISSES = [0]
LOOK = int(arg("--look", "24"))
COMPS = ["main", "contrib", "non-free", "non-free-firmware"]
ARCHS = ["amd64", "i386", "arm64"]
LOGF = open(os.path.join(RES, "run.log"), "a")


def log(msg):
    LOGF.write(time.strftime("%Y-%m-%dT%H:%M:%S ") + msg + "\n")
    LOGF.flush()


def url(ts, path):
    return fetch.BASE + ts + "/" + path


def get(ts, path):
    """Fetch with an on-disk cache under DATA/<ts>/<path> (404s cached as .404)."""
    fn = os.path.join(DATA, ts, path)
    if os.path.exists(fn):
        with open(fn, "rb") as fh:
            return fh.read()
    if os.path.exists(fn + ".404"):
        return None
    if OFFLINE and not re.search(r"(/Packages(\.xz|\.bz2|\.gz)?|/Release)$", path):
        OFFLINE_MISSES[0] += 1
        return None
    data = fetch.get(url(ts, path), log)
    os.makedirs(os.path.dirname(fn), exist_ok=True)
    if data is None:
        open(fn + ".404", "w").close()
        return None
    with open(fn + ".tmp", "wb") as fh:
        fh.write(data)
    os.replace(fn + ".tmp", fn)
    return data


download = get


def decompress(name, data):
    if name.endswith(".xz"):
        return lzma.decompress(data)
    if name.endswith(".bz2"):
        return bz2.decompress(data)
    if name.endswith(".gz"):
        return gzip.decompress(data)
    return data


# ---------------------------------------------------------------- timestamps
def timestamps():
    cache = os.path.join(DATA, "timestamps.json")
    if os.path.exists(cache):
        return json.load(open(cache))
    out = []
    y, m = 2012, 1
    now = time.gmtime()
    while (y, m) <= (now.tm_year, now.tm_mon):
        html = fetch.get(f"{fetch.BASE}?year={y}&month={m}", log)
        if html is None:
            log(f"no listing for {y}-{m}")
        else:
            out += re.findall(r'href="(\d{8}T\d{6}Z)/"', html.decode("ascii", "replace"))
        m += 1
        if m > 12:
            y, m = y + 1, 1
    out = sorted(set(out))
    json.dump(out, open(cache, "w"))
    return out


# ---------------------------------------------------------------- Release
def parse_release(text):
    fields, sums, cur = {}, {}, None
    for line in text.splitlines():
        if not line:
            continue
        if line[0] == " ":
            if cur:
                p = line.split()
                if len(p) == 3:
                    sums.setdefault(cur, {})[p[2]] = (p[0], int(p[1]))
            continue
        k, _, v = line.partition(":")
        cur = None
        if k in ("MD5Sum", "SHA1", "SHA256", "SHA512"):
            cur = k
        else:
            fields[k] = v.strip()
    return fields, sums


# ---------------------------------------------------------------- per-file stream
class Stream:
    def __init__(self, comp, arch):
        self.comp, self.arch = comp, arch
        self.path = f"dists/sid/{comp}/binary-{arch}/Packages"
        self.lines = None     # list of bytes lines
        self.sha1 = self.sha256 = None
        self.look = None      # (ts, merged, hist[(h, size, name)], cur_hash, alg, patches{name: hash})
        self.missing_since = None
        self.lookn = 4

    def set_content(self, data):
        self.lines = data.splitlines(keepends=True)
        self.sha1 = hashlib.sha1(data).hexdigest()
        self.sha256 = hashlib.sha256(data).hexdigest()
        return data

    def ours(self, alg):
        return self.sha256 if alg == "sha256" else self.sha1


def load_index(ts, st):
    raw = get(ts, st.path + ".diff/Index")
    if raw is None:
        return None
    fields, lists = parse_index(raw.decode("utf-8", "replace"))
    # use whichever algorithm has the longer history (dak added SHA256 lists
    # in Dec 2015 starting from an empty history)
    alg = "sha256" if len(lists.get("sha256-history", [])) >= len(lists.get("sha1-history", [])) \
        and "sha256-history" in lists else "sha1"
    cur = fields.get(f"{alg}-current", "").split()
    # Prefer the unmerged chain: in the merged era dak still ships the
    # per-dinstall patches (X-Unmerged-*), which persist across snapshots.
    pre = f"x-unmerged-{alg}" if f"x-unmerged-{alg}-history" in lists else alg
    def nogz(n):
        # dak briefly (late 2020) wrote history names with a .gz suffix
        return n[:-3] if n.endswith(".gz") else n
    hist = [(h, s, nogz(n)) for h, s, n in lists.get(f"{pre}-history", [])]
    patches = {nogz(n): h for h, s, n in lists.get(f"{pre}-patches", [])}
    dl = {n: h for h, s, n in lists.get(f"{pre}-download", [])}
    merged = pre == alg and (fields.get("x-patch-precedence", "") == "merged"
                             or any(n.startswith("T-") for _, _, n in hist))
    return {"ts": ts, "merged": merged, "hist": hist, "cur": cur[0] if cur else None,
            "alg": alg, "patches": patches, "download": dl, "fields": fields}


def fname(n):
    # original (unmerged) patch name of a merged history entry
    m = re.match(r"^T-(.+)-F-(.+)$", n)
    return m.group(2) if m else n


def plan(idx, st, targets):
    """Return list of (ts, filename, expected uncompressed hash|None, alg) or None."""
    alg = idx["alg"]
    ours = st.ours(alg)
    target = targets.get(alg)
    if target is None:
        return None
    hashes = [h for h, _, _ in idx["hist"]]
    if ours not in hashes:
        return None
    a = hashes.index(ours)
    if target == idx["cur"]:
        b = len(hashes)
    elif target in hashes:
        b = hashes.index(target)
    else:
        return None
    if b <= a:
        return None
    names = [n for _, _, n in idx["hist"]]
    after = hashes[1:] + [idx["cur"]]
    if not idx["merged"]:
        return [(idx["ts"], n + ".gz", idx["patches"].get(n), alg, n, after[a + k])
                for k, n in enumerate(names[a:b])]
    if b == len(hashes):
        n = names[a]
        return [(idx["ts"], n + ".gz", idx["patches"].get(n), alg, n, idx["cur"])]
    # merged patch from state a to state b lives in the snapshot where b is current
    return [(None, f"T-{fname(names[b - 1])}-F-{fname(names[a])}.gz", None, alg,
             fname(names[b - 1]), hashes[b])]


def try_pdiff(st, ts, ts_list, i, targets):
    """Advance st to target via pdiffs.
    Returns (data|None, npatches, intermediates[(name, lines, verified)])."""
    if OFFLINE:
        cands = [ts_list[j] for j in range(min(i + 60, len(ts_list) - 1), i - 1, -1)
                 if os.path.exists(os.path.join(DATA, ts_list[j], st.path + ".diff/Index"))]
        attempts = ["cached"] + ["off:" + t for t in cands]
    else:
        attempts = ["cached", "look", "here"]
    for attempt in attempts:
        if attempt.startswith("off:"):
            if st.look and st.look["ts"] == attempt[4:]:
                continue
            idx = load_index(attempt[4:], st)
        elif attempt == "cached":
            idx = st.look
        elif attempt == "look":
            lts = ts_list[min(i + st.lookn, len(ts_list) - 1)]
            if st.look and st.look["ts"] == lts:
                continue
            idx = load_index(lts, st)
        else:
            if st.look and st.look["ts"] == ts:
                continue
            idx = load_index(ts, st)
        if idx is None:
            continue
        if attempt != "cached":
            st.look = idx
            # look ahead about half the pdiff window (in snapshot states)
            st.lookn = max(1, min(LOOK, len(idx["hist"]) // 2 - 1))
        p = plan(idx, st, targets)
        if p is None:
            continue
        lines = st.lines
        ok = True
        inters = []
        for pts, fn, ph, alg, pname, after in p:
            raw = download(pts or ts, st.path + ".diff/" + fn)
            if raw is None:
                log(f"{ts} {st.path}: patch {fn} missing at {pts or ts}")
                ok = False
                break
            try:
                patch = gzip.decompress(raw)
            except Exception as e:
                log(f"{ts} {st.path}: patch {fn} bad gzip {e!r}")
                ok = False
                break
            if ph and getattr(hashlib, alg)(patch).hexdigest() != ph:
                log(f"{ts} {st.path}: patch {fn} hash mismatch")
                ok = False
                break
            try:
                lines = apply_ed(lines, patch)
            except PatchError as e:
                log(f"{ts} {st.path}: patch {fn} apply error {e}")
                ok = False
                break
            inters.append((pname, lines, after))
        if ok:
            out = []
            if INTER:
                for pname, ls, after in inters[:-1]:
                    h = getattr(hashlib, alg)(b"".join(ls)).hexdigest()
                    out.append((pname, ls, h == after))
            return b"".join(lines), len(p), out
    return None, 0, []


def seed(st, ts, files):
    for ext in (".xz", ".bz2", ".gz", ""):
        name = st.path[len("dists/sid/"):] + ext
        if name not in files:
            continue
        raw = download(ts, st.path + ext)
        if raw is None:
            continue
        try:
            return decompress(ext, raw), ext or "plain"
        except Exception as e:
            log(f"{ts} {st.path}{ext}: decompress error {e!r}")
    return None, None


def save(state, cov, pos, streams, meta):
    tmp = os.path.join(RES, "checkpoint.pkl.tmp")
    with open(tmp, "wb") as fh:
        pickle.dump({"occ": state.occ.d, "any_atoms": state.any_atoms,
                     "qual_all": state.qual_atoms_all,
                     "qual_prov": state.qual_atoms_with_provider,
                     "pos": pos, "meta": meta, "scanned": state.stanzas_scanned}, fh)
    os.replace(tmp, os.path.join(RES, "checkpoint.pkl"))


def main():
    tsl = [t for t in timestamps() if START <= t <= END]
    log(f"start: {len(tsl)} timestamps {tsl[0]}..{tsl[-1]}")
    state = State()
    meta = {"states": 0, "verified": {"sha256": 0, "sha1": 0, "md5": 0, "none": 0},
            "method": {}, "requests0": 0}
    first = 0
    ck = os.path.join(RES, "checkpoint.pkl")
    if os.path.exists(ck) and "--resume" in ARGS:
        d = pickle.load(open(ck, "rb"))
        state.occ.d = d["occ"]
        state.any_atoms = d["any_atoms"]
        state.qual_atoms_all = d["qual_all"]
        state.qual_atoms_with_provider = d["qual_prov"]
        state.stanzas_scanned = d["scanned"]
        meta = d["meta"]
        first = tsl.index(d["pos"]) + 1
        log(f"resume after {d['pos']}")
    streams = {(c, a): Stream(c, a) for c in COMPS for a in ARCHS}
    cov = open(os.path.join(RES, "coverage.tsv"), "a")
    icov = open(os.path.join(RES, "intermediate.tsv"), "a")
    t0 = time.time()
    n = 0
    for i in range(first, len(tsl)):
        ts = tsl[i]
        rel = get(ts, "dists/sid/Release")
        if rel is None:
            log(f"{ts}: no sid Release")
            cov.write(f"{ts}\tNO-RELEASE\n")
            continue
        fields, sums = parse_release(rel.decode("utf-8", "replace"))
        archs = set(fields.get("Architectures", "").split())
        comps = set(fields.get("Components", "").split())
        alg = "SHA256" if "SHA256" in sums else "SHA1" if "SHA1" in sums else "MD5Sum"
        files = sums.get(alg, {})
        row = [ts]
        byname, pending, inter_row = {}, [], []
        for (c, a), st in streams.items():
            key = f"{c}/binary-{a}/Packages"
            code = "-"
            if c not in comps or a not in archs or (key not in files and not any(
                    k.startswith(key + ".") for k in files)):
                if st.lines is not None:
                    state.set_file(c, a, None)
                    st.lines = None
                    st.sha1 = st.sha256 = None
                    st.look = None
                    log(f"{ts}: {key} disappeared")
                row.append("-")
                continue
            target = files.get(key, (None,))[0]
            have = {"SHA256": st.sha256, "SHA1": st.sha1}.get(alg)
            if target is not None and st.lines is not None and have == target:
                row.append("=")
                continue
            data, how, inters = None, None, []
            if st.lines is not None and target is not None:
                targets = {"sha256": sums.get("SHA256", {}).get(key, (None,))[0],
                           "sha1": sums.get("SHA1", {}).get(key, (None,))[0]}
                data, np_, inters = try_pdiff(st, ts, tsl, i, targets)
                if data is not None:
                    how = f"P{np_}"
            if data is not None:
                st.set_content(data)
                ok = {"SHA256": st.sha256, "SHA1": st.sha1}.get(alg) == target
                if not ok:
                    log(f"{ts} {key}: pdiff result checksum mismatch; re-seeding")
                    data = None
                    inters = []
            if data is None:
                data, ext = seed(st, ts, files)
                if data is None:
                    log(f"{ts} {key}: GAP no usable full file")
                    if st.lines is not None:
                        state.set_file(c, a, None)
                    st.lines = None
                    st.sha1 = st.sha256 = None
                    row.append("GAP")
                    continue
                st.set_content(data)
                how = "S" + ext
            hv = {"SHA256": st.sha256, "SHA1": st.sha1}.get(alg)
            if target is None:
                # no uncompressed checksum: compare compressed? record unverified
                vtag = "none"
            elif hv == target:
                vtag = alg.lower()
            else:
                log(f"{ts} {key}: seed checksum MISMATCH (have {hv}, want {target})")
                vtag = "MISMATCH"
            meta["verified"][vtag] = meta["verified"].get(vtag, 0) + 1
            meta["method"][how[0]] = meta["method"].get(how[0], 0) + 1
            for pname, ls, ver in inters:
                byname.setdefault(pname, []).append((c, a, ls, ver))
            row.append(None)
            pending.append((len(row) - 1, c, a, data, f"{how}:{vtag[:2]}"))
        # intermediate dinstall states (not captured by snapshot), in dinstall order
        for pname in sorted(byname):
            for c, a, ls, ver in byname[pname]:
                state.set_file(c, a, split_stanzas(b"".join(ls)))
                k = "verified" if ver else "unverified"
                meta.setdefault("inter", {}).setdefault(k, 0)
                meta["inter"][k] += 1
            m = re.match(r"^(\d{4})-(\d\d)-(\d\d)-(\d\d)(\d\d)\.(\d\d)$", pname)
            label = ("".join(m.groups()[:3]) + "T" + "".join(m.groups()[3:]) + "D") if m else "D:" + pname
            state.evaluate(label)
            meta["inter_states"] = meta.get("inter_states", 0) + 1
            inter_row.append(f"{ts}\t{label}\t" + ",".join(f"{c}/{a}{'' if v else '!'}" for c, a, _, v in byname[pname]))
        for j, c, a, data, tag in pending:
            added, removed = state.set_file(c, a, split_stanzas(data))
            row[j] = f"{tag}:+{added}-{removed}"
        if i == first and "--warm-first" in ARGS:
            # segment overlap: this state belongs to the previous segment; only seed
            # it (dirty sets are kept, so the next evaluate covers everything)
            continue
        state.evaluate(ts)
        if inter_row:
            icov.write("\n".join(inter_row) + "\n")
        meta["states"] += 1
        cov.write("\t".join(row) + "\n")
        n += 1
        if n % 25 == 0:
            cov.flush()
            save(state, cov, ts, streams, meta)
            el = time.time() - t0
            log(f"progress {ts} ({i + 1}/{len(tsl)}) {n / el:.3f} st/s req={fetch.STATS} "
                f"scanned={state.stanzas_scanned} occ={len(state.occ.d)}")
        if LIMIT and n >= LIMIT:
            break
    cov.flush()
    icov.flush()
    save(state, cov, tsl[i], streams, meta)
    log(f"done at {tsl[i]} req={fetch.STATS} offline_misses={OFFLINE_MISSES[0]}")


if __name__ == "__main__":
    main()
