//! First of all, I want to say that I'm sorry about the name, I just couldn't help myself.
#![no_std]
#![no_main]
#![warn(clippy::pedantic)]

mod app;
mod initramfs;
extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

use dlmalloc::Dlmalloc;

#[global_allocator]
static ALLOCATOR: SingleThreadedAlloc = SingleThreadedAlloc::new();

struct SingleThreadedAlloc {
    inner: UnsafeCell<Dlmalloc>,
}

impl SingleThreadedAlloc {
    pub(crate) const fn new() -> Self {
        SingleThreadedAlloc {
            inner: UnsafeCell::new(Dlmalloc::new()),
        }
    }
}

unsafe impl GlobalAlloc for SingleThreadedAlloc {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        (*self.inner.get()).malloc(layout.size(), layout.align())
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        (*self.inner.get()).free(ptr, layout.size(), layout.align())
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        (*self.inner.get()).calloc(layout.size(), layout.align())
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        (*self.inner.get()).realloc(ptr, layout.size(), layout.align(), new_size)
    }
}

/// Extremely unsafe, this program is not thread safe at all will immediately segfault on more threads
unsafe impl Sync for SingleThreadedAlloc {}

unsafe impl Send for SingleThreadedAlloc {}

#[no_mangle]
fn main() -> i32 {
    app::run();
    0
}
