"""pdiff Index parsing and ed-script application (as APT does)."""
import re


class PatchError(Exception):
    pass


def parse_index(text):
    """Parse a Packages.diff/Index.  Returns dict:
    fields: {lower-name: value}; lists: {lower-name: [(hash, size, name)]}."""
    fields, lists, cur = {}, {}, None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[0] in " \t":
            if cur is None:
                continue
            parts = line.split()
            if len(parts) == 3:
                lists.setdefault(cur, []).append((parts[0], int(parts[1]), parts[2]))
            continue
        k, _, v = line.partition(":")
        k = k.strip().lower()
        v = v.strip()
        if v:
            fields[k] = v
            cur = None
        else:
            cur = k
            lists.setdefault(k, [])
    return fields, lists


_CMD = re.compile(rb"^(\d+)(?:,(\d+))?([acd])$")


def parse_ed(patch):
    """Parse an ed script (diff --ed output) into hunks (start, end, cmd, lines).
    Line numbers are 1-based in the ORIGINAL file; commands appear in
    descending order."""
    lines = patch.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    hunks = []
    i = 0
    n = len(lines)
    while i < n:
        m = _CMD.match(lines[i])
        if not m:
            if lines[i] == b"w" or lines[i] == b"q":
                i += 1
                continue
            raise PatchError(f"bad ed command {lines[i][:80]!r}")
        a = int(m.group(1))
        b = int(m.group(2)) if m.group(2) else a
        c = m.group(3)
        i += 1
        body = []
        if c in b"ac":
            while True:
                if i >= n:
                    raise PatchError("unterminated ed text")
                if lines[i] == b".":
                    i += 1
                    break
                body.append(lines[i] + b"\n")
                i += 1
            # 's/.//' idiom: a line '..' stands for '.'
            if i < n and lines[i] == b"s/.//":
                i += 1
                if body:
                    body[-1] = body[-1][1:]
        hunks.append((a, b, c, body))
    return hunks


def apply_ed(old_lines, patch):
    """old_lines: list of bytes lines each ending in b'\\n'.  Returns new list."""
    hunks = parse_ed(patch)
    # diff --ed emits hunks bottom-up; replay them top-down in one pass.
    # Out-of-order or overlapping hunks raise PatchError below.
    hunks.reverse()
    out = []
    pos = 0  # 0-based index into old_lines of next unconsumed line
    n = len(old_lines)
    for a, b, c, body in hunks:
        if c == b"a":
            # append after line a
            if a < pos or a > n:
                raise PatchError(f"append position {a} out of range")
            out.extend(old_lines[pos:a])
            out.extend(body)
            pos = a
        else:
            if a < 1 or b < a or a - 1 < pos or b > n:
                raise PatchError(f"range {a},{b}{c!r} out of range (pos {pos}, n {n})")
            out.extend(old_lines[pos:a - 1])
            if c == b"c":
                out.extend(body)
            pos = b
    out.extend(old_lines[pos:])
    return out
