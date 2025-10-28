#![feature(link_llvm_intrinsics)]
#![feature(allow_internal_unsafe)]
#![allow(internal_features)]

use std::mem::transmute;

pub fn magic<T>(x: &mut T) -> (&mut T, &mut T) {
    (unsafe { transmute(&mut *x) }, x)
}

unsafe extern "C" {
    #[link_name = "llvm.addressofreturnaddress"]
    pub fn _address_of_return_address() -> *const u8;
}

#[allow_internal_unsafe]
#[macro_export]
macro_rules! address_of_return_address {
    () => {
        unsafe { $crate::_address_of_return_address() }
    };
}
