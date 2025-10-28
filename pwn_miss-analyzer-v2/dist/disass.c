#include "out.h"



int _init(EVP_PKEY_CTX *ctx)

{
  int iVar1;
  
  iVar1 = __gmon_start__();
  return iVar1;
}



void FUN_00401020(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void free(void *__ptr)

{
  free(__ptr);
  return;
}



void seccomp_init(void)

{
  seccomp_init();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int putchar(int __c)

{
  int iVar1;
  
  iVar1 = putchar(__c);
  return iVar1;
}



void seccomp_rule_add(void)

{
  seccomp_rule_add();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int puts(char *__s)

{
  int iVar1;
  
  iVar1 = puts(__s);
  return iVar1;
}



void seccomp_load(void)

{
  seccomp_load();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t strlen(char *__s)

{
  size_t sVar1;
  
  sVar1 = strlen(__s);
  return sVar1;
}



void __stack_chk_fail(void)

{
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int printf(char *__format,...)

{
  int iVar1;
  
  iVar1 = printf(__format);
  return iVar1;
}



void seccomp_release(void)

{
  seccomp_release();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memset(__s,__c,__n);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

size_t strcspn(char *__s,char *__reject)

{
  size_t sVar1;
  
  sVar1 = strcspn(__s,__reject);
  return sVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * malloc(size_t __size)

{
  void *pvVar1;
  
  pvVar1 = malloc(__size);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int setvbuf(FILE *__stream,char *__buf,int __modes,size_t __n)

{
  int iVar1;
  
  iVar1 = setvbuf(__stream,__buf,__modes,__n);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

__ssize_t getline(char **__lineptr,size_t *__n,FILE *__stream)

{
  __ssize_t _Var1;
  
  _Var1 = getline(__lineptr,__n,__stream);
  return _Var1;
}



void FUN_00401220(int param_1)

{
                    // WARNING: Subroutine does not return
  exit(param_1);
}



void processEntry _start(undefined8 param_1,undefined8 param_2)

{
  undefined1 auStack_8 [8];
  
  __libc_start_main(main,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



void _dl_relocate_static_pie(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x0040127d)
// WARNING: Removing unreachable block (ram,0x00401287)

void deregister_tm_clones(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x004012bf)
// WARNING: Removing unreachable block (ram,0x004012c9)

void register_tm_clones(void)

{
  return;
}



void __do_global_dtors_aux(void)

{
  if (completed_0 == '\0') {
    deregister_tm_clones();
    completed_0 = 1;
    return;
  }
  return;
}



void frame_dummy(void)

{
  register_tm_clones();
  return;
}



undefined8 hexchr2bin(char param_1,char *param_2)

{
  undefined8 uVar1;
  
  if (param_2 == (char *)0x0) {
    uVar1 = 0;
  }
  else {
    if ((param_1 < '0') || ('9' < param_1)) {
      if ((param_1 < 'A') || ('F' < param_1)) {
        if ((param_1 < 'a') || ('f' < param_1)) {
          return 0;
        }
        *param_2 = param_1 + -0x57;
      }
      else {
        *param_2 = param_1 + -0x37;
      }
    }
    else {
      *param_2 = param_1 + -0x30;
    }
    uVar1 = 1;
  }
  return uVar1;
}



ulong hexs2bin(char *param_1,long *param_2)

{
  int iVar1;
  void *pvVar2;
  ulong uVar3;
  long in_FS_OFFSET;
  char local_22;
  byte local_21;
  ulong local_20;
  size_t local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (((param_1 == (char *)0x0) || (*param_1 == '\0')) || (param_2 == (long *)0x0)) {
    uVar3 = 0;
  }
  else {
    local_18 = strlen(param_1);
    if ((local_18 & 1) == 0) {
      local_18 = local_18 >> 1;
      pvVar2 = malloc(local_18);
      *param_2 = (long)pvVar2;
      memset((void *)*param_2,0x41,local_18);
      for (local_20 = 0; uVar3 = local_18, local_20 < local_18; local_20 = local_20 + 1) {
        iVar1 = hexchr2bin((int)param_1[local_20 * 2],&local_22);
        if ((iVar1 == 0) ||
           (iVar1 = hexchr2bin((int)param_1[local_20 * 2 + 1],&local_21), iVar1 == 0)) {
          uVar3 = 0;
          break;
        }
        *(byte *)(local_20 + *param_2) = (byte)((int)local_22 << 4) | local_21;
      }
    }
    else {
      uVar3 = 0;
    }
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar3;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



undefined1 read_byte(long *param_1,long *param_2)

{
  undefined1 uVar1;
  
  if (*param_2 == 0) {
    puts("Error: failed to read replay");
    FUN_00401220(1);
  }
  uVar1 = *(undefined1 *)*param_1;
  *param_1 = *param_1 + 1;
  *param_2 = *param_2 + -1;
  return uVar1;
}



int read_short(undefined8 param_1,undefined8 param_2)

{
  char cVar1;
  char cVar2;
  
  cVar1 = read_byte(param_1,param_2);
  cVar2 = read_byte(param_1,param_2);
  return (int)((double)(int)(short)cVar1 + (double)(int)(short)cVar2 * 256.0);
}



void read_string(undefined8 param_1,undefined8 param_2,undefined1 *param_3,uint param_4)

{
  uint uVar1;
  byte bVar2;
  char cVar3;
  undefined1 uVar4;
  uint local_24;
  uint local_1c;
  
  *param_3 = 0;
  cVar3 = read_byte(param_1,param_2);
  if (cVar3 != '\0') {
    if (cVar3 != '\v') {
      puts("Error: failed to read string");
      FUN_00401220(1);
    }
    local_24 = 0;
    bVar2 = 0;
    while( true ) {
      cVar3 = read_byte(param_1,param_2);
      local_24 = local_24 | ((int)cVar3 & 0x7fU) << (bVar2 & 0x1f);
      if (-1 < cVar3) break;
      bVar2 = bVar2 + 7;
    }
    local_1c = 0;
    while( true ) {
      uVar1 = param_4;
      if (local_24 < param_4) {
        uVar1 = local_24;
      }
      if (uVar1 <= local_1c) break;
      uVar4 = read_byte(param_1,param_2);
      param_3[(int)local_1c] = uVar4;
      local_1c = local_1c + 1;
    }
    for (; local_1c < local_24; local_1c = local_1c + 1) {
      read_byte(param_1,param_2);
    }
    if (param_4 <= local_24) {
      local_24 = param_4;
    }
    param_3[local_24] = 0;
  }
  return;
}



void consume_bytes(undefined8 param_1,undefined8 param_2,int param_3)

{
  undefined4 local_c;
  
  for (local_c = 0; local_c < param_3; local_c = local_c + 1) {
    read_byte(param_1,param_2);
  }
  return;
}



undefined8
main(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,undefined8 param_5,
    undefined8 param_6)

{
  char *pcVar1;
  char cVar2;
  short sVar3;
  int iVar4;
  undefined8 uVar5;
  __ssize_t _Var6;
  size_t sVar7;
  long in_FS_OFFSET;
  char *local_158;
  size_t local_150;
  void *local_148;
  long local_140;
  void *local_138;
  long local_130;
  char local_128 [264];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  local_130 = seccomp_init(0x7fff0000);
  if (local_130 == 0) {
    puts("Error: failed to initialize seccomp");
    uVar5 = 1;
  }
  else {
    iVar4 = seccomp_rule_add(local_130,0,0x3b,0,param_5,param_6,param_2);
    if (iVar4 < 0) {
      puts("Error: failed to add seccomp rule");
      seccomp_release(local_130);
      uVar5 = 1;
    }
    else {
      iVar4 = seccomp_rule_add(local_130,0,0x142,0,param_5,param_6,param_2);
      if (iVar4 < 0) {
        puts("Error: failed to add seccomp rule");
        seccomp_release(local_130);
        uVar5 = 1;
      }
      else {
        iVar4 = seccomp_load(local_130);
        if (iVar4 < 0) {
          puts("Error: failed to load seccomp filter");
          seccomp_release(local_130);
          uVar5 = 1;
        }
        else {
          puts("Submit replay as hex (use xxd -p -c0 replay.osr | ./analyzer):");
          local_158 = (char *)0x0;
          local_150 = 0;
          _Var6 = getline(&local_158,&local_150,stdin);
          pcVar1 = local_158;
          if (_Var6 < 1) {
            uVar5 = 1;
          }
          else {
            sVar7 = strcspn(local_158,"\n");
            pcVar1[sVar7] = '\0';
            if (*local_158 == '\0') {
              uVar5 = 1;
            }
            else {
              local_140 = hexs2bin(local_158,&local_148);
              local_138 = local_148;
              if (local_140 == 0) {
                puts("Error: failed to decode hex");
                uVar5 = 1;
              }
              else {
                puts("\n=~= miss-analyzer =~=");
                cVar2 = read_byte(&local_138,&local_140);
                if (cVar2 == '\0') {
                  puts("Mode: osu!");
                }
                else if (cVar2 == '\x01') {
                  puts("Mode: osu!taiko");
                }
                else if (cVar2 == '\x02') {
                  puts("Mode: osu!catch");
                }
                else if (cVar2 == '\x03') {
                  puts("Mode: osu!mania");
                }
                consume_bytes(&local_138,&local_140,4);
                read_string(&local_138,&local_140,local_128,0xff);
                printf("Hash: %s\n",local_128);
                read_string(&local_138,&local_140,local_128,0xff);
                printf("Player name: ");
                printf(local_128);
                putchar(10);
                read_string(&local_138,&local_140,local_128,0xff);
                consume_bytes(&local_138,&local_140,10);
                sVar3 = read_short(&local_138,&local_140);
                printf("Miss count: %d\n",(ulong)(uint)(int)sVar3);
                if (sVar3 == 0) {
                  puts("You didn\'t miss!");
                }
                else {
                  puts("Yep, looks like you missed.");
                }
                puts("=~=~=~=~=~=~=~=~=~=~=\n");
                free(local_158);
                free(local_148);
                seccomp_release(local_130);
                uVar5 = 0;
              }
            }
          }
        }
      }
    }
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return uVar5;
}



void _fini(void)

{
  return;
}

