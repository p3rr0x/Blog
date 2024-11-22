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
