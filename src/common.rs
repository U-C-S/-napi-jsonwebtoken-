pub fn throw_napi_error<T>(status: napi::Status, message: &str) -> napi::Result<T> {
    napi::Result::Err(napi::Error::new(status, message.to_owned()))
}
