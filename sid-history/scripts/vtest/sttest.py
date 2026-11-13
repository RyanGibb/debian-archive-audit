import sys; sys.path.insert(0, sys.argv[1])
from scanstate import State
s = State()
A = [b"Package: a\nVersion: 1.0\nArchitecture: amd64\nConflicts: b:any (>= 1), c:i386\nProvides: x:any\n",
     b"Package: b\nVersion: 1.00\nArchitecture: amd64\nDepends: foo:native, bar:all\nconflicts: q | r\n",
     b"Package: b\nVersion: 1.0\nArchitecture: amd64\nMulti-Arch: allowed\n",
     b"Package: d\nVersion: 2\nArchitecture: amd64\nProvides: c\n",
     b"Package: e\nVersion: 2\nProvides: c (= 3)\nVersion: 3\n"]
s.set_file("main", "amd64", A); s.evaluate("T1")
s.set_file("main", "amd64", A[:2]); s.evaluate("T2")
for k, v in sorted(s.occ.d.items()): print(k, v[:3], v[3])
print(s.any_atoms, s.qual_atoms_with_provider)
