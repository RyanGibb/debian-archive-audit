import random, subprocess, sys
sys.path.insert(0, sys.argv[1])
from debver import vcmp
random.seed(1)
al = "0123456789.~+-:abzAZ"
def rv():
    s = random.choice("0123456789") + "".join(random.choice(al) for _ in range(random.randint(0, 8)))
    if random.random() < .3: s = str(random.randint(0, 12)) + ":" + s
    return s
fixed = [("1.0","1.00"),("0:1","1"),("1.0~rc1","1.0"),("1.0-1","1.0-1~"),("1:0","0:9"),("1.0a","1.0+"),("1.0","1.0-0"),("01","1"),("1.0.","1.0"),("1~","1"),("1-0","1")]
pairs = fixed + [(rv(), rv()) for _ in range(200000)]
out = subprocess.run([sys.argv[2]], input="\n".join(f"{a} {b}" for a, b in pairs), capture_output=True, text=True).stdout.split()
bad = [(a, b, o, vcmp(a, b)) for (a, b), o in zip(pairs, out) if o != "X" and (vcmp(a, b) > 0) - (vcmp(a, b) < 0) != int(o)]
print(sum(o == "X" for o in out), "invalid skipped")
print(len(pairs), "pairs;", len(bad), "mismatches", bad[:5])
for a, b in fixed: print(a, b, vcmp(a, b))
