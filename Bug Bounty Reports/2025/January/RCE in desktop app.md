
When opening a link from ringcentral chat a verification is made on the URL path with the following regex

*LINK_PATH_REG = /^\/regex1\/regex2\/regex3\/(.+)/*

Since there is no verification for the URL host the following link will create a new renderer process

*https://test.p3rr0.com/regex1/regex2/regex3/x*

For the new renderer process, once the document is loaded an internal electron event is emitted **"WINDOW_MANAGER_SET_ENV"** to set the context for internal IPC events.
This event is executed through the internal listener located at **node:electron/js2c/sandbox_bundle**
![image](https://github.com/user-attachments/assets/2c33533b-5838-4867-bde4-30d5b1fe54ea)

As seen in the following screenshot, the variable **arguments** contains 3 elements

![image](https://github.com/user-attachments/assets/233335cb-cad0-4f8d-9c25-855e9b15dae7)
