//! Secret buffers backed by dedicated, page-aligned allocations.

use std::alloc::{Layout, alloc, dealloc, handle_alloc_error};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::slice;

use zeroize::Zeroize;

/// A fixed-size secret stored in its own page-aligned allocation.
///
/// Locking is best effort: if the platform does not support `mlock`, or the
/// process has exhausted its lock allowance, the allocation remains usable and
/// is still zeroized before being released.
pub struct LockedSecret<const N: usize> {
    allocation: LockedAllocation,
}

impl<const N: usize> LockedSecret<N> {
    /// Move a secret into a dedicated allocation and attempt to page-lock it.
    #[must_use]
    pub fn new(mut value: [u8; N]) -> Self {
        let mut allocation = LockedAllocation::new(N);
        allocation.as_mut_slice().copy_from_slice(&value);
        value.zeroize();
        Self { allocation }
    }

    /// Whether this allocation was successfully page-locked.
    #[must_use]
    pub const fn is_locked(&self) -> bool {
        self.allocation.locked
    }
}

impl<const N: usize> Deref for LockedSecret<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        self.allocation
            .as_slice()
            .try_into()
            .expect("locked secret allocation has its declared length")
    }
}

impl<const N: usize> DerefMut for LockedSecret<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.allocation
            .as_mut_slice()
            .try_into()
            .expect("locked secret allocation has its declared length")
    }
}

/// A runtime-length secret stored in its own page-aligned allocation.
pub struct LockedBytes {
    allocation: LockedAllocation,
}

impl LockedBytes {
    pub fn new(mut value: Vec<u8>) -> Self {
        let mut allocation = LockedAllocation::new(value.len());
        allocation.as_mut_slice().copy_from_slice(&value);
        value.zeroize();
        Self { allocation }
    }
}

impl Deref for LockedBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.allocation.as_slice()
    }
}

impl DerefMut for LockedBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.allocation.as_mut_slice()
    }
}

struct LockedAllocation {
    ptr: NonNull<u8>,
    len: usize,
    layout: Layout,
    locked: bool,
}

impl LockedAllocation {
    fn new(len: usize) -> Self {
        let page_size = page_size();
        let allocation_size = len.max(1).div_ceil(page_size) * page_size;
        let layout = Layout::from_size_align(allocation_size, page_size)
            .expect("platform page size produces a valid allocation layout");
        // SAFETY: `layout` has non-zero size and valid power-of-two alignment.
        let ptr = unsafe { alloc(layout) };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
        let locked = lock(ptr, allocation_size);
        #[cfg(target_os = "macos")]
        if !locked {
            eprintln!(
                "warning: could not lock secret memory for sshenv runtime hardening: {}",
                std::io::Error::last_os_error()
            );
        }
        Self {
            ptr,
            len,
            layout,
            locked,
        }
    }

    const fn as_slice(&self) -> &[u8] {
        // SAFETY: the allocation remains live for `self`, and `len` is no
        // greater than the allocation size.
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    const fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `&mut self` provides exclusive access to the live allocation,
        // and `len` is no greater than the allocation size.
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for LockedAllocation {
    fn drop(&mut self) {
        self.as_mut_slice().zeroize();
        if self.locked {
            unlock(self.ptr, self.layout.size());
        }
        // SAFETY: `ptr` was returned by `alloc` with this exact layout and has
        // not previously been deallocated.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

#[cfg(unix)]
fn page_size() -> usize {
    // SAFETY: `sysconf` has no pointer or memory-safety preconditions.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(value)
        .ok()
        .filter(|value| value.is_power_of_two())
        .unwrap_or(4096)
}

#[cfg(not(unix))]
const fn page_size() -> usize {
    4096
}

#[cfg(target_os = "macos")]
fn lock(ptr: NonNull<u8>, len: usize) -> bool {
    // SAFETY: `ptr..ptr+len` names the live allocation owned by the caller.
    unsafe { libc::mlock(ptr.as_ptr().cast(), len) == 0 }
}

#[cfg(not(target_os = "macos"))]
const fn lock(_ptr: NonNull<u8>, _len: usize) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn unlock(ptr: NonNull<u8>, len: usize) {
    // SAFETY: the region was successfully locked and remains allocated.
    unsafe {
        libc::munlock(ptr.as_ptr().cast(), len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_secret_is_aligned_and_read_write() {
        let mut secret = LockedSecret::new([7_u8; 32]);
        assert_eq!(secret.as_slice(), &[7_u8; 32]);
        secret[0] = 9;
        assert_eq!(secret[0], 9);
        assert_eq!((secret.as_ptr() as usize) % page_size(), 0);
    }

    #[test]
    fn separate_secrets_do_not_share_pages() {
        let first = LockedSecret::new([1_u8; 32]);
        let second = LockedSecret::new([2_u8; 32]);
        let first_page = first.as_ptr() as usize / page_size();
        let second_page = second.as_ptr() as usize / page_size();
        assert_ne!(first_page, second_page);
    }

    #[test]
    fn runtime_secret_handles_empty_and_nonempty_values() {
        let empty = LockedBytes::new(Vec::new());
        assert!(empty.is_empty());
        assert_eq!((empty.as_ptr() as usize) % page_size(), 0);

        let mut bytes = LockedBytes::new(vec![1, 2, 3]);
        bytes[1] = 4;
        assert_eq!(&*bytes, &[1, 4, 3]);
        assert_eq!((bytes.as_ptr() as usize) % page_size(), 0);
    }
}
