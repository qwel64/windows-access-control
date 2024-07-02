# windows-access-control
A lightweight Windows utility for advanced directory access management. Easily restrict or grant access to specific folders, enhancing system security and user privacy. Ideal for admins and security-conscious users.

Specify the paths to apply_restriction.cpp and remove_restriction.cpp  
Set path `LPCWSTR path = L"C:\\Path";`  
Path example `LPCWSTR path = L"C:\\Users\\user\\Downloads";`

`#include<windows.h>`
`#include <aclapi.h>` is installed by default in windows


The developer assumes no responsibility for any damage or issues arising from the use of this tool. Use at your own risk.
