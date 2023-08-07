#![no_std]
#![no_main]

mod app;

extern crate alloc;

#[no_mangle]
extern "Rust" fn main() -> i32 {
    if let Err(exit) = app::main_loop() {
        exit
    } else {
        0
    }
}
