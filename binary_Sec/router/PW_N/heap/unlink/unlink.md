# Unlink
## Overview
- When executing `free(chunk)`:
  - `glibc` will first determine the type of `chunk` to be released. If it is `small chunk` or `large chunk`, it needs to be merged.
  - Judge forward merge (low address). If the previous `chunk` is in idle state, then forward merge
  - Judge backward merge (high address). If the latter `chunk` is in an idle state, backward merge is performed
  - The `chunk` that the heap needs to be merged to perform `unlink` operation

- `unlink` is a macro defined in `libc`. The definition of `unlink` is found in `malloc.c` as follows:

```c
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {
    FD = P->fd;
    BK = P->bk;
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);
    else {
        FD->bk = BK;
        BK->fd = FD;
        if (!in_smallbin_range (P->size)
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {
	    if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)
		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))
	      malloc_printerr (check_action,
			       "corrupted double-linked list (not small)",
			       P, AV);
            if (FD->fd_nextsize == NULL) {
                if (P->fd_nextsize == P)
                  FD->fd_nextsize = FD->bk_nextsize = FD;
                else {
                    FD->fd_nextsize = P->fd_nextsize;
                    FD->bk_nextsize = P->bk_nextsize;
                    P->fd_nextsize->bk_nextsize = FD;
                    P->bk_nextsize->fd_nextsize = FD;
                  }
              } else {
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;
              }
          }
      }
}
```

- The `_int_free` function was executed when executing the `free` function, and the `unlink` macro was called in the `_int_free` function:

```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size; /* its size */
  mfastbinptr *fb; /* associated fastbin */
  mchunkptr nextchunk; /* next continuous chunk */
  INTERNAL_SIZE_T nextsize; /* its size */
  int nextinuse; /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize; /* size of previous continuous chunk */
  mchunkptr bck; /* misc temp for linking */
  mchunkptr fwd; /* misc temp for linking */

  const char *errstr = NULL;
  int locked = 0;

  size = chunksize (p);

  /* Little security check which won't hurt performance: the
     allocator never wraps around at the end of the address space.
     Therefore we can exclude some size values ​​which might appear
     here by accident or by "design" from some intruder. */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    {
      errstr = "free(): invalid pointer";
    errout:
      if (!have_lock && locked)
        (void) mutex_unlock (&av->mutex);
      malloc_printerr (check_action, errstr, chunk2mem (p), av);
      return;
    }
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT. */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    {
      errstr = "free(): invalid size";
      goto error;
    }

  check_inuse_chunk(av, p);

  /*
    If eligible, place chunk on a fastbin so it can be found
    and used quickly in malloc.
  */

  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {

    if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
	/* We might not have a lock at this point and concurrent modifications
	   of system_mem might have let to a false positive. Redo the test
	   After gett
ing the lock. */
	if (have_lock
	    || ({ assert (locked == 0);
		  mutex_lock(&av->mutex);
		  locked = 1;
		  chunk_at_offset (p, size)->size <= 2 * SIZE_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem;
	      }))
	  {
	    errstr = "free(): invalid next size (fast)";
	    goto error;
	  }
	if (! have_lock)
	  {
	    (void)mutex_unlock(&av->mutex);
	    locked = 0;
	  }
      }

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

    set_fastchunks(av);
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P; */
    mchunkptr old = *fb, old2;
    unsigned int old_idx = ~0u;
    do
      {
	/* Check that the top of the bin is not the record we are going to add
	   (i.e., double free). */
	if (__builtin_expect (old == p, 0))
	  {
	    errstr = "double free or corruption (fasttop)";
	    goto error;
	  }
	/* Check that size of fastbin chunk at the top is the same as
	   size of the chunk that we are adding. We can dereference OLD
	   Only if we have the lock, otherwise it might have already been
	   deallocated. See use of OLD_IDX below for the actual check. */
	if (have_lock && old != NULL)
	  old_idx = fastbin_index(chunksize(old));
	p->fd = old2 = old;
      }
    while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2);

    if (have_lock && old != NULL && __builtin_expect (old_idx != idx, 0))
      {
	errstr = "invalid fastbin entry (free)";
	goto error;
      }
  }

  /*
    Consolidate other non-mmapped chunks as they arrive.
  */

  else if (!chunk_is_mmapped(p)) {
    if (! have_lock) {
      (void)mutex_lock(&av->mutex);
      locked = 1;
    }

    nextchunk = chunk_at_offset(p, size);

    /* Lightweight tests: check whether the block is already the
       top block. */
    if (__glibc_unlikely (p == av->top))
      {
	errstr = "double free or corruption (top)";
	goto error;
      }
    /* Or whether the next chunk is beyond the boundaries of the arena. */
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
      {
	errstr = "double free or corruption (out)";
	goto error;
      }
    /* Or whether the block is actually not marked used. */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      {
	errstr = "double free or corruption (!prev)";
	goto error;
      }

    nextsize = chunksize(nextchunk);
    if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      {
	errstr = "free(): invalid next size (normal)";
	goto error;
      }

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }

    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
	unlink(av, nextchunk, bck, fwd);
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);

      /*
	Place the chunk in unsorted chunk list. Chunks are
	Not placed into regular bins until after they have
	have been given one chance to be used in malloc.
      */

      bck = unsorted_chunks(av);
      fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
	{
	  errstr = "free(): corrupted unsorted chunks";
	  goto error;
	}
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
	{
	  p->fd_nextsize = NULL;
	  p->bk_nextsize = NULL;
	}
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);

      check_free_chunk(av, p);
    }

    /*
      If the chunk borders the current high end of memory,
      Consolidate into top
    */

    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top =
p;
      check_chunk(av, p);
    }

    /*
      If freeing a large space, consolidate possible-surrounding
      chunks. Then, if the total unused topmost memory exceeds trim
      threshold, ask malloc_trim to reduce top.

      Unless max_fast is 0, we don't know if there are fastbins
      bordering top, so we cannot tell for sure whether threshold
      has been reached unless fastbins are consolidated. But we
      Don't want to consolidate on each free. As a compromise,
      consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
      is reached.
    */

    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
      if (have_fastchunks(av))
	malloc_consolidate(av);

      if (av == &main_arena) {
#ifndef MORECORE_CANNOT_TRIM
	if ((unsigned long)(chunksize(av->top)) >=
	    (unsigned long)(mp_.trim_threshold))
	  systrim(mp_.top_pad, av);
#endif
      } else {
	/* Always try heap_trim(), even if the top chunk is not
	   large, because the corresponding heap might go away. */
	heap_info *heap = heap_for_ptr(top(av));

	assert(heap->ar_ptr == av);
	heap_trim(heap, mp_.top_pad);
      }
    }

    if (! have_lock) {
      assert (locked);
      (void)mutex_unlock(&av->mutex);
    }
  }
  /*
    If the chunk was allocated via mmap, release via munmap().
  */

  else {
    munmap_chunk (p);
  }
}
```

## Vulnerability Principle


- The following is to understand the principle of `unlink` through code debugging. `7 `chunks` were applied for in the sample code, and then `first_chunk`, `second_chunk`, and `third_chunk` are released in turn.
- Release these `chunks` is because the `chunk` with adjacent addresses will be merged after being released. When the addresses are not adjacent, they will not merge. Since the `chunk` of `0x80` is applied, they will not enter `fastbin` after being released, but will first enter `unsortbin`
- Since the environment is `glibc 2.31`, use the tool `glibc-all-in-one` to download the required version of glibc`, and then use the tool `patchelf` to replace the program's `glibc`: `patchelf --set-interpreter /home/h3rmesk1t/glibc-all-in-one/libs/2.23-0ubuntu3_amd64/ld-2.23.so --set-rpath /home/h3rmesk1t/glibc-all-in-one/libs/2.23-0ubuntu3_amd64 test`

```c
#include <stdio.h>
#include <stdlib.h>

void main()
{
	long *first_chunk = malloc(0x80);
	long *second_chunk = malloc(0x80);
	long *third_chunk = malloc(0x80);
	long *fouth_chunk = malloc(0x80);
	long *fifth_chunk = malloc(0x80);
	long *sixth_chunk = malloc(0x80);
	
	free(first_chunk);
	free(third_chunk);
	free(fouth_chunk);
	
	return 0;
}
```

- Use `gdb` to open the compiled example. Because the `-g` parameter is used, use the command `b 17` to breakpoint on line `17. Next, use the command `r` to make the program run. Use the command `bin` to see the arrangement structure in the bidirectional linked list. Use the `heap` command to view these `free` `chunk`

![](images/1.png#pic_center)

```
first_chunk_bk -> third_chunk
third_chunk_bk -> fifth_chunk
fifth_chunk_fd -> third_chunk
third_chunk_fd -> first_chunk
```

![](images/2.png#pic_center)

- The purpose and process of `unlink` is to take out the free blocks in a bidirectional linked list, for example, when `free` is merged with the currently physically adjacent `free chunk`. When using the vulnerability caused by `unlink`, it is actually to layout the `chunk` memory, and then use the `unlink` operation to achieve the effect of modifying the pointer.
- The process of `unlink` is roughly as follows:
  - First, based on the `fd` pointer and `bk` pointer of `chunk P`, the chunks before and after `bin` are `FD` and `BK` respectively
  - Then let the `chunk FD`' pointer point to `chunk BK`
  - Finally let the `chunk BK`'s `fd` pointer point to `chunk FD`


![](images/3.png#pic_center)