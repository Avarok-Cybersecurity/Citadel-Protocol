export PATH="/home/nologik/osxcross/target/bin:$PATH"
export CC=o64-clang
export CXX=o64-clang++
cargo build --release --package hyxewave --target x86_64-apple-darwin
unset CC
unset CXX