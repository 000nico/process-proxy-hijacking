# 🧠 Process Proxy 

## 📌 Overview

This project injects a payload into a process so it can <b>read and write memory for us</b>,  
so you can work with memory <b>without opening or duplicating new handles</b>.

Usage:
- load the payload with proxy::init()
- read and write with proxy::write(address, new value) and proxy::read(address)

In the example, im looking for svchost.exe, in order to read and write values of counter-strike 2
---

## ⚙️ Workflow

<ol>
  <li>Enable debug privileges</li>
  <li>Find a process that already has a handle to the target</li>
  <li>Locate where that handle is stored in memory</li>
  <li>Allocate memory in the target process</li>
  <li>Inject payload + shellcode</li>
  <li>Communicate with the payload to read/write memory</li>
</ol>

---

### <code>proxy::init</code>

<pre>
int proxy::init(ULONG accessMask, LPCSTR windowName, bool debug)
</pre>

<b>Main entry point. Executes the full chain.</b>

<b>Parameters</b>

<ul>
  <li><code>accessMask</code>: the permissions we are looking for</li>
  <li><code>windowName</code>: the window the handle should point to</li>
  <li><code>debug</code>: true or false, depending on whether we want to see what the program is doing</li>
</ul>

<b>Returns</b>

<ul>
  <li><code>1</code> → success</li>
  <li><code>2</code> → failed enabling SeDebugPrivilege</li>
  <li><code>3</code> → failed finding process with handle</li>
  <li><code>4</code> → failed finding handle address</li>
  <li><code>5</code> → failed allocating memory</li>
  <li><code>6</code> → failed injecting payload</li>
</ul>

---

### <code>proxy::enableSeDebugPrivilege</code>

<pre>
bool proxy::enableSeDebugPrivilege()
</pre>

Enables <b>SeDebugPrivilege</b> to allow interaction with external processes.

---

### <code>proxy::findProcessWithHandle</code>

<pre>
int proxy::findProcessWithHandle(
    ULONG accessMask,
    LPCSTR windowName,
    DWORD* processPIDBuffer,
    HANDLE* duplicatedHandleBuffer,
    USHORT* originalHandleValue
)
</pre>

Finds a process that already has a handle to the target window.

<b>Parameters</b>

<ul>
  <li><code>accessMask</code>: set the permissions you are looking for</li>
  <li><code>windowName</code>: "Counter - Strike 2"</li>
  <li><code>processPIDBuffer</code>: pointer to a DWORD that will receive the PID of the process holding the handle</li>
  <li><code>duplicatedHandleBuffer</code>: pointer to a HANDLE that will receive the duplicated handle (optional)</li>
  <li><code>originalHandleValue</code>: pointer to a USHORT that will receive the original handle value</li>
</ul>

---

### <code>proxy::findAddressWithHandle</code>

<pre>
int proxy::findAddressWithHandle(
    HANDLE handle,
    DWORD pid,
    uintptr_t* foundAtAddress,
    LPCSTR windowName
)
</pre>

Searches inside the process memory to find where the handle is stored.

<b>Parameters</b>

<ul>
  <li><code>handle</code>: the handle we are looking for</li>
  <li><code>pid</code>: the PID of the process where we are searching</li>
  <li><code>foundAtAddress</code>: pointer to a uintptr_t that will contain the address where the handle is stored</li>
  <li><code>windowName</code>: the window the handle should point to</li>
</ul>


---

### <code>proxy::prepareCodeInjection</code>

<pre>
int proxy::prepareCodeInjection(
    DWORD pid,
    LPVOID* rShellCodeBaseAddress,
    LPVOID* wShellCodeBaseAddress,
    LPVOID* rBufferBaseAddress,
    LPVOID* wBufferBaseAddress,
    LPVOID* structBaseAddress
)
</pre>

Allocates memory in the target process.

<b>Parameters</b>

<ul>
  <li><code>pid</code>: PID of the target process that has the handle</li>
  <li><code>rShellCodeBaseAddress</code>: pointer that will receive the base address where read shellcode is allocated</li>
  <li><code>wShellCodeBaseAddress</code>: pointer that will receive the base address where write shellcode is allocated</li>
  <li><code>rBufferBaseAddress</code>: pointer that will receive the base address where read values are stored</li>
  <li><code>wBufferBaseAddress</code>: pointer that will receive the base address where values to write are stored</li>
  <li><code>structBaseAddress</code>: pointer that will receive the base address where the payload struct is stored</li>
</ul>

<b>Allocations</b>

---

### <code>payload::load</code>

<pre>
int payload::load(
    DWORD pid,
    uintptr_t readShellCodeBaseAddress,
    uintptr_t handleAddress,
    uintptr_t readBufferAddress,
    uintptr_t structBaseAddress
)
</pre>

Injects the payload into the target process.

<b>Parameters</b>

<ul>
  <li><code>pid</code>: PID of the target process that has the handle</li>
  <li><code>readShellCodeBaseAddress</code>: address where the shellcode was allocated</li>
  <li><code>handleAddress</code>: address where the process stores the desired handle</li>
  <li><code>readBufferAddress</code>: address where read values are stored</li>
  <li><code>structBaseAddress</code>: address where the payload struct was allocated</li>
</ul>

---

## 📝 Notes

<ul>
  <li>Uses undocumented NT APIs (<code>NtQuerySystemInformation</code>)</li>
  <li>Needs <b>SeDebugPrivilege</b></li>
  <li>Assumes target window exists</li>
</ul>

---

## ⚠️ Warnings

<ul>
  <li>Do not use on software you don’t own or don’t have permission to analyze</li>
</ul>

---
