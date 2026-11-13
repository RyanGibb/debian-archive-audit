"""dpkg version comparison and relation-atom parsing.

Adapted from audit-scripts/scan_lib.py; character classes made ASCII-only to
match dpkg's c_isdigit/c_isalpha (lib/dpkg/version.c, verrevcmp/order), and
epoch/revision split made to follow lib/dpkg/parsehelp.c parseversion.
"""
import re


def _isdigit(c):
    return "0" <= c <= "9"


def _isalpha(c):
    return ("a" <= c <= "z") or ("A" <= c <= "Z")


def order(c):
    # c is a 1-char string, or "" for end of string
    if not c:
        return 0
    if _isdigit(c):
        return 0
    if _isalpha(c):
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def verrevcmp(a, b):
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and not _isdigit(a[i])) or (j < lb and not _isdigit(b[j])):
            ac = order(a[i]) if i < la else 0
            bc = order(b[j]) if j < lb else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and _isdigit(a[i]) and j < lb and _isdigit(b[j]):
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and _isdigit(a[i]):
            return 1
        if j < lb and _isdigit(b[j]):
            return -1
        if first_diff:
            return first_diff
    return 0


_EPOCH = re.compile(r"^[ \t]*([+-]?[0-9]+):(.+)$")


def split_ver(v):
    """Return (epoch, upstream, revision) as dpkg parseversion does
    (epoch via strtol up to the first ':', revision after the last '-')."""
    v = v.strip()
    e = 0
    if ":" in v:
        m = _EPOCH.match(v)
        if m:
            e, v = int(m.group(1)), m.group(2)
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, ""
    return e, up, rev


def vcmp(a, b):
    ea, ua, ra = split_ver(a)
    eb, ub, rb = split_ver(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = verrevcmp(ua, ub)
    if c:
        return c
    return verrevcmp(ra, rb)


def sat(v, op, w):
    """Does version v satisfy (op w)?  op None = unversioned."""
    if op is None:
        return True
    c = vcmp(v, w)
    return {"<<": c < 0, "<=": c <= 0, "<": c <= 0, "=": c == 0,
            ">=": c >= 0, ">": c >= 0, ">>": c > 0, "": c == 0}[op]


ALT = re.compile(
    r"^\s*(?P<name>[^\s:(\[<|,]+)(?::(?P<qual>[^\s(\[<|,]+))?\s*"
    r"(?:\(\s*(?P<op><<|<=|>=|>>|=|<|>|)\s*(?P<ver>[^)\s]*)\s*\))?\s*"
    r"(?P<arch>\[[^\]]*\])?\s*(?P<prof>(?:<[^>]*>\s*)*)$", re.S)


def parse_field(text):
    """List of clauses; each clause a list of (raw, groupdict|None); None for empty clause."""
    clauses = []
    for clause in text.split(","):
        if not clause.strip():
            clauses.append(None)
            continue
        alts = []
        for alt in clause.split("|"):
            m = ALT.match(alt)
            alts.append((" ".join(alt.split()), m.groupdict() if m else None))
        clauses.append(alts)
    return clauses
