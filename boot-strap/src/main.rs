//! First of all, I want to say that I'm sorry about the name, I just couldn't help myself.
#![no_std]
#![no_main]
#![warn(clippy::pedantic)]
#![allow(clippy::similar_names)]

mod app;
mod initramfs;
extern crate alloc;

#[no_mangle]
fn main() -> i32 {
    app::run();
    0
}
