# Chunk Extend and Overlapping
## Overview
- `chunk extend` is a common method of exploitation in heap vulnerabilities. The effect of `chunk overlapping` can be achieved through `extend`. This method needs to meet the following conditions:
  - Heap-based vulnerability exists in the program
  - Vulnerability can control data in `chunk header`

- `ptmalloc` determines the usage of chunk` and locates the front and back blocks of chunk` through the data of chunk header. `chunk extend` is to control the `pre_size` field and `size` field to achieve cross-block operations, resulting in `overlapping`
- Generally speaking, this technology cannot directly control the execution process of the program, but it can control the content in `chunk`. If `chunk` has string pointers, function pointers, etc., these pointers can be used to leak information and control the execution process.
- In addition, `chunk overlapping` can be implemented through `extend`, and `fd` pointer and `bk` pointer of `chunk` can be controlled through `overlapping`, so that `fastbin attack` can be implemented and other uses

## Vulnerability Principle
### extend the fastbin of inuse
- Sample Code

```c
#include <stdlib.h>
#include <stdio.h>

int main()
{
    void *ptr1, *ptr2;

    ptr1 = malloc(0x10); // Allocate chunk1 with size 0x10
    ptr2 = malloc(0x10); // Allocate chunk2 with size 0x10

    *(long long *)((long long)ptr1 - 0x8) = 0x41; // Modify the size field of chunk1

    free(ptr1); // Release chunk1

    ptr1 = malloc(0x30); // Implement extend
    return 0;
}
```

- After two `chunks with size of `0x10`, the heap distribution is shown in the figure

![](images/1.png#pic_center)

- Then change the `size` field value of `chunk1` to `0x41`. `0x41` is because the `size` field of `chunk` contains the user-controlled size and the `chunk header` size. In the question or actual application, this step can be obtained by heap overflow.
- Then perform the `free` operation, you can see that `chunk1` and `chunk2` are merged into a `0x40` size `chunk` is released

![](images/2.png#pic_center)

- Then, the heap blocks of `chunk1+chunk2` are obtained through `malloc(0x30)`, and the contents in `chunk2` can be directly controlled. This state is called `overlapping chunk`

![](images/3.png#pic_center)

### extend the smallbin of inuse
- Sample Code

```c
#include <stdlib.h>
#include <stdio.h>

int main()
{
    void *ptr, *ptr1;

    ptr=malloc(0x80);// Allocate chunk1 with size 0x80
    malloc(0x10); //Assign a second 0x10 chunk2
    malloc(0x10); // Prevent merging with top chunk

    *(int *)((int)ptr - 0x8) = 0xb1;
    free(ptr);

    ptr1 = malloc(0xa0);
    return 0;
}
```

- In the above example code, since the allocated `size` is not in the range of `fastbin`, if connected to `top chunk` during release, it will cause merging with `top chunk`, so an additional `chunk` is needed to separate the released chunk from `top chunk`
- After `malloc`three blocks`chunk`, the heap distribution is shown in the figure

![](images/4.png#pic_center)

- Then change the `size` field value of `chunk1` to `0xb1`

![](images/5.png#pic_center)

- Then `free` drop `chunk1`, `chunk1` swallows the content of `chunk2` and puts it in `unsorted bin` together

![](images/6.png#pic_center)

- When allocating again, the spaces of `chunk1` and `chunk2` will be retrieved, and the contents in `chunk2` can be controlled at this time.

![](images/7.png#pic_center)

### extend free smallbin
- Sample Code

```c
#include <stdlib.h>
#include <stdio.h>

int main() {
    void *ptr, *ptr1;

    ptr = malloc(0x80); // Allocate chunk1 with size 0x80
    malloc(0x10); // Allocate chunk2 with size 0x10

    free(ptr); // Release first, so that chunk1 enters unsorted bin

    *(long long*)((long long)ptr - 0x8) = 0xb1;
    ptr1 = malloc(0xa0);
	
	return 0;
}
```

- In this utilization method, first release `chunk1`, and then modify the `size` field of `chunk1` in `unsorted bin`
- After two `malloc`chunk`, the heap distribution is shown in the figure

![](images/8.png#pic_center)

- Then `free`drop`chunk1` first and let it enter `unsorted bin`

![](images/9.png#pic_center)

- Then change the `size` field value of `chunk1` to `0xb1`

![](images/10.png#pic_center)


- Then perform the `malloc` allocation and you can get the heap blocks of `chunk1+chunk2`, thereby controlling the contents of `chunk2`

![](images/11.png#pic_center)

## Vulnerability Exploit
- Normally, the `Chunk Extend/Shrink` technology cannot directly control the execution process of the program, but can control the content in `chunk`
- If `chunk` has string pointers, function pointers, etc., these pointers can be used to leak information and control execution process
- In addition, `chunk overlapping` can be implemented through `extend`, and `fd/bk` pointer of `chunk` can be controlled so that `fastbin attack` can be implemented and other uses

#### Backward overlapping via extend
- Sample Code

```c
#include <stdlib.h>
#include <stdio.h>

int main()
{
    void *ptr, *ptr1;

    ptr = malloc(0x10);//Assign the first 0x80 chunk1
    malloc(0x10); //Assign the second 0x10 chunk2
    malloc(0x10); //Assign the third 0x10 chunk3
    malloc(0x10); //Assign the 4th 0x10 chunk4
	
    *(long long *)((long long)ptr - 0x8) = 0x61;
    free(ptr);
	
    ptr1 = malloc(0x50);
	return 0;
}
```

- After the `malloc(0x50)` re-occupy the `extend` area, the `fastbin` block of `0x10` can still be allocated and released normally. At this time, it has constituted `overlapping`. `fastbin attack` can be implemented by operating `overlapping`.

![](images/12.png#pic_center)

![](images/13.png#pic_center)

### Forward overlapping by extend
- Sample Code

```c
#include <stdlib.h>
#include <stdio.h>

int main(void)
{
    void *ptr1, *ptr2, *ptr3, *ptr4;
    ptr1 = malloc(128); // smallbin1
    ptr2 = malloc(0x10); // fastbin1
    ptr3 = malloc(0x10); // fastbin2
    ptr4 = malloc(128); // smallbin2
    malloc(0x10); // Prevent merging with top
	
    free(ptr1);
    *(long long *)((long long)ptr4 - 0x8) = 0x90; // Modify the pre_inuse domain
    *(long long *)((long long)ptr4 - 0x10) = 0xd0;
// Modify the pre_size domain
    free(ptr4); // unlink performs forward extension
    malloc(0x150); // Placeholder block

	return 0;
}
```

- Merge the previous blocks by modifying the `pre_inuse` domain and the `pre_size` domain
- Forward `extend` utilizes the `unlink` mechanism of `small bin`. By modifying the `pre_size` field, it can merge multiple `chunks` to achieve `overlapping`

![](images/14.png#pic_center)

![](images/15.png#pic_center)