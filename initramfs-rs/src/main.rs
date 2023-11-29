#![no_std]
#![no_main]

mod app;

extern crate alloc;

#[no_mangle]
fn main() -> i32 {
    if let Err(exit) = app::main_loop() {
        exit
    } else {
        0
    }
}
