set CC=C:/android-ndk-r21d/toolchains/llvm/prebuilt/windows-x86_64/bin/x86_64-linux-android30-clang.cmd
set AR=C:/android-ndk-r21d/toolchains/llvm/prebuilt/windows-x86_64/bin/x86_64-linux-android-ar

cargo build --package hyxewave --target=aarch64-linux-android

set CC=
set AR=