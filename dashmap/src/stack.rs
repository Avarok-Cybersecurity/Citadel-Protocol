//! Please see the struct level documentation.

use ccl_crossbeam_epoch::{self as epoch, Atomic, Guard, Owned, Pointer};
use std::mem;
use std::ptr;
use std::sync::atomic::Ordering;

/// Aquire a guard. These are needed when accessing a stack. Since aquiring a guard has a significant cost,
/// you may wish to aquire a guard once and pass it around when doing bulk operations.
/// For most use cases you will not need this.
///
/// Please note that no memory consumed by objects removed after the guard was aquired can be reclaimed
/// until the guard has been dropped.
#[inline(always)]
pub fn aquire_guard() -> Guard {
    epoch::pin()
}

/// ConcurrentStack is a general purpose threadsafe and lockfree FILO/LIFO stack.
pub struct ConcurrentStack<T> {
    head: Atomic<Node<T>>,
}

impl<T> Drop for ConcurrentStack<T> {
    #[inline]
    fn drop(&mut self) {
        let guard = &aquire_guard();
        let head = self.head.load(Ordering::SeqCst, guard);

        if !head.is_null() {
            unsafe {
                guard.defer_destroy(head);
            }
        }
    }
}

struct Node<T> {
    data: T,
    next: Atomic<Node<T>>,
}

impl<T> Drop for Node<T> {
    #[inline]
    fn drop(&mut self) {
        let guard = &aquire_guard();
        let next = self.next.load(Ordering::SeqCst, guard);

        if !next.is_null() {
            unsafe {
                guard.defer_destroy(next);
            }
        }
    }
}

impl<T> ConcurrentStack<T> {
    /// Create a new, empty stack.
    pub fn new() -> Self {
        Self {
            head: Atomic::null(),
        }
    }

    /// Push an element to the top of the stack.
    #[inline]
    pub fn push(&self, data: T) {
        let guard = &aquire_guard();
        self.push_with_guard(data, guard);
    }

    /// Pop the uppermost element of the stack.
    #[inline]
    pub fn pop(&self) -> Option<T> {
        let guard = &aquire_guard();
        self.pop_with_guard(guard)
    }

    /// Create an iterator over all elements in the stack.
    #[inline]
    pub fn pop_iter(&self) -> StackIter<T> {
        StackIter {
            guard: aquire_guard(),
            stack: &self,
        }
    }

    /// Push an element with an existing guard.
    #[inline]
    pub fn push_with_guard(&self, data: T, guard: &Guard) {
        let mut node = Owned::new(Node {
            data,
            next: Atomic::null(),
        });

        loop {
            let head = self.head.load(Ordering::SeqCst, guard);

            node.next.store(head, Ordering::SeqCst);

            match self
                .head
                .compare_and_set(head, node, Ordering::SeqCst, guard)
            {
                Ok(_) => return,
                Err(err) => node = err.new,
            }
        }
    }

    /// Pop an element with an existing guard.
    #[inline]
    pub fn pop_with_guard(&self, guard: &Guard) -> Option<T> {
        loop {
            let head_ptr = self.head.load(Ordering::SeqCst, guard);

            match unsafe { head_ptr.as_ref() } {
                Some(head) => unsafe {
                    let next = head.next.load(Ordering::SeqCst, guard);

                    if let Ok(head_ptr) =
                        self.head
                            .compare_and_set(head_ptr, next, Ordering::SeqCst, guard)
                    {
                        guard.defer_unchecked(move || {
                            mem::drop(Box::from_raw(head_ptr.into_usize() as *mut u8));
                        });

                        return Some(ptr::read(&(*head).data));
                    }
                },
                None => return None,
            }
        }
    }
}

impl<T> Default for ConcurrentStack<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// An iterator over a stack.
pub struct StackIter<'a, T> {
    guard: Guard,
    stack: &'a ConcurrentStack<T>,
}

impl<'a, T> Iterator for StackIter<'a, T> {
    type Item = T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.stack.pop_with_guard(&self.guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rayon::prelude::*;

    #[test]
    fn insert_then_pop_assert_1024_st() {
        let stack = ConcurrentStack::new();

        for _ in 0..1024_i32 {
            stack.push(9);
        }

        for _ in 0..1024_i32 {
            assert_eq!(9, stack.pop().unwrap());
        }
    }

    #[test]
    fn insert_then_pop_assert_rayon() {
        let stack = ConcurrentStack::new();

        let iter_c: i32 = 1024 * 1024;

        (0..iter_c).into_par_iter().for_each(|_| {
            stack.push(9);
        });

        (0..iter_c).into_par_iter().for_each(|_| {
            assert_eq!(9, stack.pop().unwrap());
        });
    }
}
