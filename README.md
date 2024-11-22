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
If both arrays point at the same address, we can store an object in obj_arr[0], in memory obj_arr[0] will contain the address of the object. Then we can get it’s address by reading fl_arr[0], because fl_arr[0] is pointing at obj_arr[0], accesing fl_arr[0] returns the literal value in memory of obj_arr[0]

![image](https://github.com/user-attachments/assets/9457df1b-6887-461e-a3d8-d436176d5068)

