# Zynamic

Zynamic is a source code recovery tool created to dynamically replace symbols at runtime in cases where the original source code is not accessible. It operates using a concept called reflective PE loading and leverages Microsoft PDB format to exchange symbol addresses with their counterparts in a source code representation.

For instance, if you want to replace a function like my_function() from binary A, you only need to provide an equivalent my_function() in a new source code representation. Zynamic will automatically handle this substitution, assuming that the function signatures match.

Unfortunately, this repository houses an outdated version - latest one being lost a long time ago. Still, It reached a state that suited my needs at the time and is now archived.

###### In this screenshot, you can see "g_loadingassets" symbol substitution. The global variable it interacted with, and the calling procedure it executed, all redirected to the new source state representation through Zynamic.

![Screenshot_2022-02-11_205921](https://user-images.githubusercontent.com/91024200/188689335-57951811-9a43-448b-a3a3-8d79aa149e35.png)

