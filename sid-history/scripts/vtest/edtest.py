import random, subprocess, sys, os
sys.path.insert(0, sys.argv[1]); d = sys.argv[2]
from pdiff import apply_ed
random.seed(2)
for it in range(300):
    a = [f"l{random.randint(0,30)}\n".encode() for _ in range(random.randint(0, 60))]
    b = list(a)
    for _ in range(random.randint(0, 10)):
        op = random.random()
        if op < .4 and b: del b[random.randrange(len(b))]
        elif op < .7: b.insert(random.randint(0, len(b)), f"n{random.randint(0,30)}\n".encode())
        elif b: b[random.randrange(len(b))] = f"c{random.randint(0,9)}\n".encode()
    open(f"{d}/a", "wb").write(b"".join(a)); open(f"{d}/b", "wb").write(b"".join(b))
    p = subprocess.run(["diff", "--ed", f"{d}/a", f"{d}/b"], capture_output=True).stdout
    assert apply_ed(a, p) == b, (it, p)
print("ok")
