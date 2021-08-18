
Build OpenSSL for Windows:
https://github.com/wayk/PowerSSL

Install to C:\OpenSSL-Win32 and C:\OpenSSL-Win64, placing the static builds under the "static" subdirectory for each.

cmake -G "Visual Studio 12" -T "v120_xp" -DCMAKE_PREFIX_PATH="C:\OpenSSL-Win32\static" -DMSVC_RUNTIME="static" -DBUILD_SHARED_LIBS="off" .
cmake -G "Visual Studio 12 Win64" -T "v120_xp" -DCMAKE_PREFIX_PATH="C:\OpenSSL-Win64\static" -DMSVC_RUNTIME="static" -DBUILD_SHARED_LIBS="off" .
