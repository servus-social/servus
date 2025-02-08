## Building from source

* `cargo build` - this builds the "debug" version
* `cargo build --target x86_64-unknown-linux-musl --release` - this builds the "release" version using `musl` (which you can run on your VPS, for example)
