# Penetration testing & anti-sandbox detection and anti-virtual machine debugging

## Preface

​ For the current stage of kill-free Trojans, the defense usually uses sandbox for detection, and uses virtual machines for debugging during the analysis of samples. This article provides a brief learning of anti-sandbox detection and anti-virtual machine debugging.

## Anti-VM debugging

### According to MAC address

Typically, the first three bytes of the `MAC` address identifies a provider. For example, the first three bytes of the `MAC` address corresponding to VMware` are `00-05-69`, `00-0C-29`, `00-1C-14` and `00-50-56`, the first three bytes of the `MAC` address corresponding to `VirtualBox` are `08-00-27`, the first three bytes of the `MAC` address corresponding to `Virtual PC` are `00-03-FF`, `00-15-5D`, etc., and the three bytes of the `MAC` address corresponding to `Parallels` are `00-1C-42`.

- [VMware](https://hwaddress.com/company/vmware-inc/)

```
00-05-69 00-05-69-00-00-00-00-00 - 00-05-69-FF-FF-FF
00-0C-29 00-0C-29-00-00-00-00 - 00-0C-29-FF-FF-FF
00-1C-14 00-1C-14-00-00-00 - 00-1C-14-FF-FF-FF
00-50-56 00-50-56-00-00-00-00 - 00-50-56-FF-FF-FF
```

- [PCS Systemtechnik GmbH](https://hwaddress.com/company/pcs-systemtechnik-gmbh-2/)

```
08-00-27 08-00-27-00-00-00 - 08-00-27-FF-FF-FF
```

- [Microsoft Corporation](https://hwaddress.com/company/microsoft-corporation-2/)

```
00-03-FF 00-03-FF-00-00-00 - 00-03-FF-FF-FF-FF-FF-FF
00-12-5A 00-12-5A-00-00-00 - 00-12-5A-FF-FF-FF
00-15-5D 00-15-5D-00-00-00-00 - 00-15-5D-FF-FF-FF
00-17-FA 00-17-FA-00-00-00-00 - 00-17-FA-FF-FF-FF
00-1D-D8 00-1D-D8-00-00-00-00 - 00-1D-D8-FF-FF-FF
00-22-48 00-22-48-00-00-00-00 - 00-22-48-FF-FF-FF
00-25-AE 00-25-AE-00-00-00-00 - 00-25-AE-FF-FF-FF
04-27-28 04-27-28-00-00-00 - 04-27-28-FF-FF-FF
0C-35-26 0C-35-26-00-00-00 - 0C-35-26-FF-FF-FF
14-CB-65 14-CB-65-00-00-00 - 14-CB-65-FF-FF-FF
1C-1A-DF 1C-1A-DF-00-00-00 - 1C-1A-DF-FF-FF-FF
20-16-42 20-16-42-00-00-00 - 20-16-42-FF-FF-FF
28-16-A8 28-16-A8-00-00-00 - 28-16-A8-FF-FF-FF
28-18-78 28-18-78-00-00-00 - 28-18-78-FF-FF-FF
28-EA-0B 28-EA-0B-00-00-00 - 28-EA-0B-FF-FF-FF
2C-54-91 2C-54-91-00-00-00 - 2C-54-91-FF-FF-FF
38-56-3D 38-56-3D-00-00-00 - 38-56-3D-FF-FF-FF
3C-FA-06 3C-FA-06-00-00-00 - 3C-FA-06-FF-FF-FF
40-8E-2C 40-8E-2C-00-00-00 - 40-8E-2C-FF-FF-FF
44-16-22 44-16-22-00-00-00 - 44-16-22-FF-FF-FF
4C-3B-DF 4C-3B-DF-00-00-00 - 4C-3B-DF-FF-FF-FF-FF
54-4C-8A 54-4C-8A-00-00-00 - 54-4C-8A-FF-FF-FF
5C-BA-37 5C-BA-37-00-00-00 - 5C-BA-37-FF-FF-FF
68-6C-E6 68-6C-E6-00-00-00 - 68-6C-E6-FF-FF-FF
6C-5D-3A 6C-5D-3A-00-00-00 - 6C-5D-3A-FF-FF-FF
70-BC-10 70-BC-10-00-00-00 - 70-BC-10-FF-FF-FF
70-F8-AE 70-F8-AE-00-00-00 - 70-F8-AE-FF-FF-FF
84-57-33 84-57-33-00-00-00 - 84-57-33-FF-FF-FF
90-6A-EB 90-6A-EB-00-00-00 - 90-6A-EB-FF-FF-FF
94-9A-A9 94-9A-A9-00-00-00 - 94-9A-A9-FF-FF-FF
98-5F-D3 98-5F-D3-00-00-00 - 98-5F-D3-FF-FF-FF-FF
98-7A-14 98-7A-14-00-00-00 - 98-7A-14-FF-FF-FF
9C-AA-1B 9C-AA-1B-00-00-00 - 9C-AA-1B-FF-FF-FF
A0-4A-5E A0-4A-5E-00-00-00 - A0-4A-5E-FF-FF-FF
A0-85-FC A0-85-FC-00-00-00 - A0-85-FC-FF-FF-FF
A8-8C-3E A8-8C-3E-00-00-00 - A8-8C-3E-FF-FF-FF
B8-31-B5 B8-31-B5-00-00-00 - B8-31-B5-FF-FF-FF
BC-83-85 BC-83-85-00-00-00 - BC-83-85-FF-FF-FF
C4-61-C7 C4-61-C7-00-00-00 - C4-61-C7-FF-FF-FF
C4-9D-ED C4-9D-ED-00-00-00 - C4-9D-ED-FF-FF-FF
C8-3F-26 C8-3F-26-00-00-00 - C8-3F-26-FF-FF-FF
C8-96-65 C8-96-65-00-00-00 - C8-96-65-FF-FF-FF
CC-60-C8 CC-60-C8-00-00-00 - CC-60-C8-FF-FF-FF
D8-E2-DF D8-E2-DF-00-00-00 - D8-E2-DF-FF-FF-FF-FF
DC-98-40 DC-98-40-00-00-00-00 - DC-98-40-FF-FF-FF
E4-2A-AC E4-2A-AC-00-00-00 - E4-2A-AC-FF-FF-FF
E8-A7-2F E8-A7-2F-00-00-00 - E8-A7-2F-FF-FF-FF
EC-83-50 EC-83-50-00-00-00 - EC-83-50-FF-FF-FF
F0-1D-BC F0-1D-BC-00-00-00 - F0-1D-BC-FF-FF-FF
F0-6E-0B F0-6E-0B-00-00-00 - F0-6E-0B-FF-FF-FF
F4-6A-D7 F4-6A-D7-00-00-00 - F4-6A-D7-FF-FF-FF
```

- [Parallels](https://hwaddress.com/company/parallels-inc/)

```
00-1C-42 00-1C-42-00-00-00 - 00-1C-42-FF-FF-FF
```

According to the above idea, obtain the `MAC` address of the running environment and compare the first three bytes of the `MAC` address to determine whether it is a virtual machine environment.

```go
func checkMacAddress(addrs []string) bool {
	// VMware
	for _, addr := range addrs {
		addrPrev := strings.ToUpper(strings.Replace(addr[:8], ":", "-", -1))
		if strings.Contains(addrPrev, "00-05-69") || strings.Contains(addrPrev, "00-0C-29") || strings.Contains(addrPrev, "00-1C-14") || strings.Contains(addrPrev, "00-50-56") {
			return true
		}
	}
	// VirtualBox
	for _, addr := range addrs {
		addrPrev := strings.ToUpper(strings.Replace(addr[:8], ":", "-", -1))
		if strings.Contains(addrPrev, "08-00-27") {
			return true
		}
	}
	// VirtualPC
	for _, ad
dr := range addrs {
		addrPrev := strings.ToUpper(strings.Replace(addr[:8], ":", "-", -1))
		if strings.Contains(addrPrev, "00-03-FF") || strings.Contains(addrPrev, "00-15-5D") {
			return true
		}
	}
	// Parallels
	for _, addr := range addrs {
		addrPrev := strings.ToUpper(strings.Replace(addr[:8], ":", "-", -1))
		if strings.Contains(addrPrev, "00-1C-42") {
			return true
		}
	}
	return false
}

func getMacAddress() (macAddrs []string) {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return macAddrs
	}
	for _, netInterface := range netInterfaces {
		macAddr := netInterface.HardwareAddr.String()
		if len(macAddr) == 0 {
			Continue continue
		}
		macAddrs = append(macAddrs, macAddr)
	}
	return macAddrs
}
```

###Based on folder or file information

​ In a Windows environment, if you use a virtual machine, there will usually be a path in the VMware virtual machine. There will usually be a path in the VMware virtual machine. There will usually be a path in the `VirtualBox virtual machine. There will usually be a path in the `Parallels virtual machine. Therefore, by looking for whether a specific folder or file exists on the disk, you can determine whether the current running environment is a virtual machine.

```go
func checkFilePath() bool {
	filePathOfVMware := "C:\\Program Files\\VMware\\VMware Tools"
	filePathOfVirtualBox := "C:\\Program Files\\Oracle\\VirtualBox Guest Additions"
	filePathOfParallels := "C:\\Program Files\\Parallels\\Parallels Tools"
	_, err1 := os.Stat(filePathOfVMware)
	_, err2 := os.Stat(filePathOfVirtualBox)
	_, err3 := os.Stat(filePathOfParallels)
	if err1 == nil || err2 == nil || err3 == nil {
		return true
	}
	return false
}
```

### According to the current process

​ By reading the current process information, find out whether there are processes specific to the virtual machine, such as `vmware.exe`, `vmtoolsd.exe` and `vmacthlp.exe` in VMware`, `VBoxService.exe` in VirtualBox`, `prl_tools_service.exe`, `prl_tools.exe`, `prl_cc.exe` or processes starting with `parallels`.

```go
func checkProcess() bool {
	processes, _ := process.Processes()
	for _, proc := range processes {
		name, _ := proc.Name()
		if strings.Contains(name, "vmtoolsd") || strings.Contains(name, "vmware") || strings.Contains(name, "vmacthlp") {
			return true
		} else if strings.Contains(name, "VBoxService") {
			return true
		} else if strings.Contains(name, "prl_") || strings.Contains(name, "parallels") {
			return true
		}
	}
	return false
}
```

### Based on registry information

​ You can read the registry location of the current environment host to determine whether it is in a virtual machine environment. For example, registry key `HKEY_CURRENT_USER\SOFTWARE\VMware, Inc.` can be judged; registry key `HKEY_LOCAL_MACHINE\SOFTWARE\Oracle\VirtualBox can be judged; registry key `HKEY_CURRENT_USER\Software\Parallels` can be judged.

```go
func checkRegistration() bool {
	_, err1 := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\VMware, Inc.`, registry.ALL_ACCESS)
	_, err2 := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Oracle\VirtualBox Guest Additions`, registry.ALL_ACCESS)
	_, err3 := registry.OpenKey(registry.CURRENT_USER, `Software\Parallels`, registry.ALL_ACCESS)
	fmt.Println(err1)
	fmt.Println(err2)
	fmt.Println(err3)
	if err1 == nil || err2 == nil || err3 == nil {
		return true
	}
	return false
}
```

## Anti-sandbox detection

### According to operating system language

​ Sandboxes are basically in English, so whether they are sandbox environments is determined based on whether the preferred operating system language is Chinese.

```go
func checkLanguage() bool {
	languages, _ := windows.GetUserPreferredUILanguages(windows.MUI_LANGUAGE_NAME)
	if languages[0] != "zh-CN" {
		return true
	}
	return false
}
```

### Based on operating system information

​ With the help of the `wmic` command, return the operating system information and make judgments based on the keywords in the operating system information.

```go
func checkOSInformation() bool {
	model := ""
	var cmd *exec.Cmd
	cmd = exec.Command("cmd", "/C", "wmic path Win32_ComputerSystem get Model")
	stdout, err := cmd.Output()
	if err != nil {
		return false
	}
	model = strings.ToLower(string(stdout))
	if strings.Contains(model, "VirtualBox") || strings.Contains(model, "virtual") || strings.Contains(model, "VMware") ||
		strings.Contains(model, "KVM") || strings.Contains(model, "Bochs") || strings.Contains(model, "HVM domU") || strings.Contains(model, "Parallels") {
		return true
	}
	return false
}
```

### According to physical memory

At present, most PCs have `RAM of `4GB` or more, and can detect whether `RAM is greater than `4GB` to determine whether it is a real running machine.

```go
func checkPhysicalMemory() bool {
	var mod = syscall.NewLazyDLL("kernel32.dll")
	var proc = mod.NewProc("GetPhysicallyInstalledSystemMemory")
	var mem uint64
	proc.Call(uin
tptr(unsafe.Pointer(&mem)))
	mem = mem / 1048576
	if mem < 4 {
		return true
	}
	return false
}
```

### According to the number of CPU cores

Most PCs have `4`core`CPU`, and many virtual machine sandboxes that are detected online are `2` cores. You can judge whether they are real machines or virtual sandboxes for detection by the number of cores.

```go
func checkNumberOfCPU() bool {
	cpu := runtime.NumCPU()
	fmt.Println(cpu)
	if cpu < 4 {
		return true
	}
	return false
}
```

### According to parent process

Generally speaking, the parent process of a program that is manually clicked is `explorer.exe`. Therefore, it can be simply determined that the parent process of a program is not `explorer.exe`, and it is believed that it was started by a sandbox, so that the SWD cannot further analyze the malicious program. However, this will also lead to problems. For example, after gettingshell, when trying to use the `webshell` manager/terminal to execute commands, it will lead to problems that cannot be executed. Here we will leave it to solve the problem of further learning.

​ Here is a simple idea of ​​judging whether it is a sandbox environment based on the parent process:

- Get the parent process `id` of the current process;
- Get all processes `ids` in the current environment;
- Get the process name of the parent process and compare it with `explorer.exe`. If the same is true, it is not a sandbox and can continue running the program. If the same is true, it is a sandbox and exit the program directly.

```go
func checkParentProcess() bool {
	ppid := os.Getppid()
	pids, _ := process.Pids()
	for _, pid := range pids {
		if pid == int32(ppid) {
			newProcess, _ := process.NewProcess(pid)
			name, _ := newProcess.Name()
			if name == "explorer.exe" {
				return true
			}
		}
	}
	return false
}
```

## refer to

- [Anti-VM Technology Summary](https://bbs.kanxue.com/thread-225735.htm)

- [Go-based sandbox detection](https://www.secpulse.com/archives/186371.html)