#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

// pub mod sign;
// use napi_derive::napi;

// #[cfg(all(
//   any(windows, unix),
//   target_arch = "x86_64",
//   not(target_env = "musl"),
//   not(debug_assertions)
// ))]
// #[global_allocator]
// static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[napi]
fn sum(a: i32, b: i32) -> i32 {
    a + b
}
