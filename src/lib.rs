#[macro_use]
extern crate napi_derive;

// pub mod sign;
mod sign;
pub mod types;
mod verify;
mod common;
// use napi_derive::napi;

// #[cfg(all(
//   any(windows, unix),
//   target_arch = "x86_64",
//   not(target_env = "musl"),
//   not(debug_assertions)
// ))]
// #[global_allocator]
// static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub use sign::sign;
pub use verify::verify;

#[napi]
pub fn sum(a: i32, b: i32) -> i32 {
    a + b
}
