pwndbg> checksec
File:     /home/jake/osugaming/pwn_miss-analyzer-v2/dist/analyzer
Arch:     amd64
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No


      0x7b2466e00000     0x7b2466e28000    0x28000        0x0  r--p   /home/jake/osugaming/pwn_miss-analyzer-v2/dist/libc.so.6
      0x7b2466e28000     0x7b2466fbd000   0x195000    0x28000  r-xp   /home/jake/osugaming/pwn_miss-analyzer-v2/dist/libc.so.6
      0x7b2466fbd000     0x7b2467015000    0x58000   0x1bd000  r--p   /home/jake/osugaming/pwn_miss-analyzer-v2/dist/libc.so.6
      0x7b2467015000     0x7b2467016000     0x1000   0x215000  ---p   /home/jake/osugaming/pwn_miss-analyzer-v2/dist/libc.so.6
      0x7b2467016000     0x7b246701a000     0x4000   0x215000  r--p   /home/jake/osugaming/pwn_miss-analyzer-v2/dist/libc.so.6
      0x7b246701a000     0x7b246701c000     0x2000   0x219000  rw-p   /home/jake/osugaming/pwn_miss-analyzer-v2/dist/libc.so.6
