use crate::prelude::*;
use std::pin::Pin;
use std::marker::PhantomData;
use async_std::prelude::Future;
use async_std::task::{Poll, Context};

/// An immutable version of the WriteVisitor
pub struct ReadVisitor<'visit, 'hvec: 'visit, T: ?Sized> {
    ptr: &'visit mut HyperVec<'hvec>,
    ticket_number: usize,
    _phantom: PhantomData<&'visit T>
}

unsafe impl<T: ?Sized> Send for ReadVisitor<'_, '_, T> {}

unsafe impl<T: ?Sized> Sync for ReadVisitor<'_, '_, T> {}

#[allow(unused_results)]
impl<'visit, 'hvec: 'visit, T: ?Sized> Drop for ReadVisitor<'visit, 'hvec, T> {
    fn drop(&mut self) {
        //println!("DROPPING Read Ticket {}", self.ticket_number);
        self.ptr.read_visit_done();
    }
}

impl<'visit, 'hvec: 'visit, T: ?Sized + 'hvec> ReadVisitor<'visit, 'hvec, T> {
    /// Creates a new WriteVisitor
    pub fn new(hvec_ptr: &'visit mut HyperVec<'hvec>, ticket_number: usize) -> Self {
        //println!("INIT read visitor with ticket number {}", ticket_number);
        Self { ptr: hvec_ptr, ticket_number, _phantom: PhantomData }
    }

    /// Consumes the visitor. Make sure to enter at least the number of bytes you expect to extend into the buf in `pre_alloc` (if the current len does not suffice).
    /// The input subroutine must return the number of bytes written for verification.
    ///
    /// The input subroutine will be given a possibly existent mutable reference. The mutable reference may not exist if
    /// the item is "corrupted". The object T is defined as corrupt if the following occur
    ///
    /// [1] if the object was previously visited, but the returned subroutine's written amount was greater than the `pre_alloc`, then
    /// the bytes written to memory were corrupt. As such, the user should always manually check the return statement for a [MemError] type.
    ///
    /// [2] The user returns an Error at the end of the subroutine.
    #[inline]
    pub async fn visit<Fx>(self, subroutine: Fx) -> InformationResult<'visit, Option<Box<T>>, &'hvec str> where Fx: Fn(Self) -> Result<(Option<Box<T>>, Self), (std::io::Error, Self)> {
        ReadVisitorFuture(self.ticket_number, self.ptr).await.and_then(move |_| {
            self.visit_inner(&subroutine)
        })
    }

    /// Quickly checks to see if the current writer is allowed to write, and if not, immediately returns with MemError::NOT_READY
    #[inline]
    pub unsafe fn try_visit<Fx>(self, subroutine: Fx) -> InformationResult<'visit, Option<Box<T>>, &'hvec str> where Fx: Fn(Self) -> Result<(Option<Box<T>>, Self), (std::io::Error, Self)> {
        if self.is_ready() {
            self.visit_inner(&subroutine)
        } else {
            Err(MemError::NOT_READY)
        }
    }

    #[inline]
    fn visit_inner<Fx>(self, subroutine: &Fx) -> InformationResult<'visit, Option<Box<T>>, &'hvec str> where Fx: Fn(Self) -> Result<(Option<Box<T>>, Self), (std::io::Error, Self)> {
        //println!("Will exec subroutine {}", self.ticket_number);
        let initial_write_version = self.ptr.get_write_version();

        match subroutine(self) {
            Ok((ret, this)) => {
                //println!("SUBROUTINE EXIT");
                if this.ptr.get_write_version() > initial_write_version {
                    // If this branch gets executed, then a dirty read occurred
                    Err(MemError::OUT_OF_SYNC)
                } else {
                    Ok(ret)
                }
            }

            _ => {
                Err(MemError::GENERIC("Subroutine panicked. Read invalid"))
            }
        }
    }

    #[inline]
    fn is_ready(&self) -> bool {
        self.ticket_number == self.ptr.get_read_version()
    }

    /// Returns a mutable reference to the underlying object if available
    #[inline]
    pub fn read(&mut self) -> Option<&T> {
        if self.is_ready() {
            unsafe { Some(self.ptr.cast_unchecked()) }
        } else {
            None
        }
    }

    /// Returns a mutable reference to the underlying object if available
    #[inline]
    pub fn read_array(&mut self) -> Option<&[T]> where T: Sized {
        if self.is_ready() {
            unsafe { Some(self.ptr.cast_unchecked_array()) }
        } else {
            None
        }
    }
}

struct ReadVisitorFuture<'visit, 'hvec: 'visit>(usize, &'visit mut HyperVec<'hvec>);

impl<'visit, 'hvec: 'visit> Future for ReadVisitorFuture<'visit, 'hvec> {
    type Output = InformationResult<'hvec, (), &'hvec str>;

    #[inline]
    fn poll(self: Pin<&mut Self>, _: &mut Context) -> Poll<Self::Output> {
        if self.0 == self.1.get_read_version() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
