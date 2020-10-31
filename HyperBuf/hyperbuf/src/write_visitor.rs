use crate::prelude::*;
use std::pin::Pin;
use std::marker::PhantomData;
use async_std::prelude::Future;
use async_std::task::{Poll, Context};

/// Allows asynchronous data execution once it's spot in line reaches the 'front'.
pub struct WriteVisitor<'visit, 'hvec: 'visit, T: ?Sized> {
    pub(crate) ptr: &'visit mut HyperVec<'hvec>,
    pub(crate) ticket_number: usize,
    pub(crate) bytes_written: usize,
    _phantom: PhantomData<&'visit T>,
}

unsafe impl<T: ?Sized> Send for WriteVisitor<'_, '_, T> {}

unsafe impl<T: ?Sized> Sync for WriteVisitor<'_, '_, T> {}

#[allow(unused_results)]
impl<'visit, 'hvec: 'visit, T: ?Sized> Drop for WriteVisitor<'visit, 'hvec, T> {
    fn drop(&mut self) {
        //println!("DROPPING Write Ticket {}", self.ticket_number);
        self.ptr.write_visit_done();
    }
}

impl<'visit, 'hvec: 'visit, T: ?Sized> WriteVisitor<'visit, 'hvec, T> {
    /// Creates a new WriteVisitor
    pub fn new(hvec_ptr: &'visit mut HyperVec<'hvec>, ticket_number: usize) -> Self {
        println!("INIT write visitor with ticket number {}", ticket_number);
        Self { ptr: hvec_ptr, ticket_number, _phantom: PhantomData, bytes_written: 0 }
    }

    /// Consumes the visitor. Make sure to enter at least the number of bytes you expect to extend into the buf in `pre_alloc` (if the current len does not suffice).
    /// The input subroutine must return the number of bytes written for verification.
    ///
    /// The input subroutine will be given a possibly existent mutable reference. The mutable reference may not exist if
    /// the item is "corrupted". The object T is defined as corrupt if one or more of the following occur
    ///
    /// [1] if the object was previously visited, but the returned subroutine's written amount was greater than the `pre_alloc`, then
    /// the bytes written to memory were corrupt. As such, the user should always manually check the return statement for a [MemError] type.
    ///
    /// [2] The user returns an Error at the end of the subroutine.
    #[inline]
    pub async fn visit<Fx>(self, pre_alloc: Option<usize>, subroutine: Fx) -> InformationResult<'visit, (), &'hvec [u8]> where Fx: Fn(Self) -> Result<(usize, Self), (std::io::Error, Self)> {
        if let Some(alloc) = pre_alloc {
            self.ptr.extend(alloc);
        }

        WriteVisitorFuture(self.ticket_number, self.ptr).await.and_then(move |_| {
            self.visit_inner(pre_alloc, &subroutine)
        })
    }

    /// Quickly checks to see if the current writer is allowed to write, and if not, immediately returns with MemError::NOT_READY
    #[inline]
    pub unsafe fn try_visit<Fx>(self, pre_alloc: Option<usize>, subroutine: Fx) -> InformationResult<'visit, (), &'hvec [u8]> where Fx: Fn(Self) -> Result<(usize, Self), (std::io::Error, Self)> {
        if self.is_ready() {
            self.visit_inner(pre_alloc, &subroutine)
        } else {
            Err(MemError::NOT_READY)
        }
    }

    #[inline]
    fn visit_inner<Fx>(self, pre_alloc: Option<usize>, subroutine: &Fx) -> InformationResult<'visit, (), &'hvec [u8]> where Fx: Fn(Self) -> Result<(usize, Self), (std::io::Error, Self)> {
        unsafe {
            //println!("Will exec subroutine {}", self.ticket_number);
            let initial_size = self.ptr.length();
            let pre_alloc_amt = pre_alloc.unwrap_or(0);

            match subroutine(self) {
                Ok((bytes_added, this)) => {
                    //println!("SUBROUTINE EXIT");
                    if bytes_added > initial_size + pre_alloc_amt {
                        this.ptr.corrupt = true;
                        MemError::throw_corrupt(std::mem::transmute(this.ptr.bytes()))
                    } else {
                        Ok(())
                    }
                }

                Err((_, this)) => {
                    this.ptr.corrupt = true;
                    Err(MemError::GENERIC(b"Subroutine panicked. HyperVec is now corrupted."))
                }
            }
        }
    }

    #[inline]
    fn is_ready(&self) -> bool {
        self.ticket_number == self.ptr.get_write_version()
    }

    /// Returns the number of bytes written from the use of WriteVisitor's exclusive methods (e.g., insert_sized_object)
    pub fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    /// Returns a mutable reference to the underlying object if available
    #[inline]
    pub fn write(&mut self) -> Option<&mut T> {
        if self.is_ready() {
            unsafe { Some(self.ptr.cast_unchecked_mut()) }
        } else {
            None
        }
    }

    /// Returns a mutable reference to the underlying object if available
    #[inline]
    pub fn write_array(&mut self) -> Option<&mut [T]> where T: Sized {
        if self.is_ready() {
            unsafe { Some(self.ptr.cast_unchecked_mut_array()) }
        } else {
            None
        }
    }

    #[inline]
    /// Returns an array of the underlying bytes
    pub fn write_bytes(&mut self) -> Option<&mut [u8]> {
        if self.is_ready() {
            unsafe { Some(self.ptr.cast_unchecked_mut_array()) }
        } else {
            None
        }
    }
}

struct WriteVisitorFuture<'visit, 'hvec: 'visit>(usize, &'visit mut HyperVec<'hvec>);

impl<'visit, 'hvec: 'visit> Future for WriteVisitorFuture<'visit, 'hvec> {
    type Output = InformationResult<'hvec, (), &'hvec [u8]>;

    #[inline]
    fn poll(self: Pin<&mut Self>, _: &mut Context) -> Poll<Self::Output> {
        if self.0 == self.1.get_write_version() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}