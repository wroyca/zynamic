# Zynamic

Zynamic was a dynamic binary rewriting tool that automatically substituted the *( hijacked, detioured )* symbols of a given binary at runtime with Reflective PE loading and Microsoft PDB. Rather than creating a midhook, it swapped the addresses (location) of the symbols in the target with those in the project using Zynamic by finding the same symbol by name in both debugging formats (target, project using Zynamic). 

Unfortunately, this repository contains an older version and the most recent one was lost a long time ago. It worked extremely well for my needs at the time but is no longer maintained and archived because I have no use for it anymore.

###### Screenshot showing g_loadingAssets substitution. The target symbol along with the global variable it accessed and the calling procedure it performed were all redirected to the project using Zynamic. 

![Screenshot_2022-02-11_205921](https://user-images.githubusercontent.com/91024200/188689335-57951811-9a43-448b-a3a3-8d79aa149e35.png)
