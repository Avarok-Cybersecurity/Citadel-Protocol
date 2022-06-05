#![allow(dead_code)]

pub trait Then<U, F: Fn(Self) -> U> where Self: Sized {
    fn then(self, fx: F) -> U;
}

impl<T: Sized, U, F: Fn(T) -> U> Then<U, F> for T {
    #[inline]
    fn then(self, fx: F) -> U {
        fx(self)
    }
}

pub struct IfEq<J> {
    true_value: Option<J>
}

pub struct IfNeq<J> {
    true_value: Option<J>
}

impl<J> IfEq<J> {
    pub fn if_false_then(self, lambda: impl FnOnce() -> J) -> J {
        self.true_value.unwrap_or(lambda())
    }

    pub fn if_false(self, value: J) -> J {
        self.true_value.unwrap_or(value)
    }
}

impl<J> IfNeq<J> {
    pub fn if_false_then(self, lambda: impl FnOnce() -> J) -> J {
        self.true_value.unwrap_or(lambda())
    }

    pub fn if_false(self, value: J) -> J {
        self.true_value.unwrap_or(value)
    }
}

pub trait IfEqConditional<J> where Self: PartialEq {
    fn if_eq(self, other: Self, value: J) -> IfEq<J>;
    fn if_eq_then(self, other: Self, lambda: impl FnOnce() -> J) -> IfEq<J>;
}

pub trait IfTrueConditional<J> {
    fn if_true(self, if_true: J) -> IfEq<J>;
    fn if_true_then(self, if_true: impl FnOnce() -> J) -> IfEq<J>;
    fn if_false(self, if_false: J) -> IfEq<J>;
    fn if_false_then(self, if_false: impl FnOnce() -> J) -> IfEq<J>;
}

pub trait IfNeqConditional<J> where Self: PartialEq {
    fn if_not_eq(self, other: Self, value: J) -> IfNeq<J>;
    fn if_not_eq_then(self, other: Self, lambda: impl FnOnce() -> J) -> IfNeq<J>;
}

impl<T: PartialEq, J> IfEqConditional<J> for T {
    fn if_eq(self, other: Self, value: J) -> IfEq<J> {
        if self != other {
            IfEq { true_value: None }
        } else {
            IfEq { true_value: Some(value) }
        }
    }

    fn if_eq_then(self, other: Self, lambda: impl FnOnce() -> J) -> IfEq<J> {
        if self != other {
            IfEq { true_value: None }
        } else {
            IfEq { true_value: Some(lambda()) }
        }
    }
}

impl<T: PartialEq, J> IfNeqConditional<J> for T {
    fn if_not_eq(self, other: Self, value: J) -> IfNeq<J> {
        if self != other {
            IfNeq { true_value: Some(value) }
        } else {
            IfNeq { true_value: None }
        }
    }

    fn if_not_eq_then(self, other: Self, lambda: impl FnOnce() -> J) -> IfNeq<J> {
        if self != other {
            IfNeq { true_value: Some(lambda()) }
        } else {
            IfNeq { true_value: None }
        }
    }
}

impl<J> IfTrueConditional<J> for bool {
    fn if_true(self, if_true: J) -> IfEq<J> {
        if self {
            IfEq { true_value: Some(if_true) }
        } else {
            IfEq { true_value: None}
        }
    }

    fn if_true_then(self, if_true: impl FnOnce() -> J) -> IfEq<J> {
        if self {
            IfEq { true_value: Some((if_true)()) }
        } else {
            IfEq { true_value: None }
        }
    }

    fn if_false(self, if_false: J) -> IfEq<J> {
        if !self {
            IfEq { true_value: Some(if_false) }
        } else {
            IfEq { true_value: None }
        }
    }

    fn if_false_then(self, if_false: impl FnOnce() -> J) -> IfEq<J> {
        if !self {
            IfEq { true_value: Some((if_false)()) }
        } else {
            IfEq { true_value: None }
        }
    }
}

pub trait PairMap<A, B> {
    fn map_left<U, F: FnOnce(A) -> U>(self, fx: F) -> (U, B);
    fn map_right<U, F: FnOnce(B) -> U>(self, fx: F) -> (A, U);
    fn map<U, F: FnOnce(A, B) -> U>(self, fx: F) -> U;
}

impl<A, B> PairMap<A, B> for (A, B) {
    fn map_left<U, F: FnOnce(A) -> U>(self, fx: F) -> (U, B) {
        ((fx)(self.0), self.1)
    }

    fn map_right<U, F: FnOnce(B) -> U>(self, fx: F) -> (A, U) {
        (self.0, (fx)(self.1))
    }

    fn map<U, F: FnOnce(A, B) -> U>(self, fx: F) -> U {
        (fx)(self.0, self.1)
    }
}

pub trait TriMap<A, B, C> {
    fn map_left<U, F: FnOnce(A) -> U>(self, fx: F) -> (U, B, C);
    fn map_center<U, F: FnOnce(B) -> U>(self, fx: F) -> (A, U, C);
    fn map_right<U, F: FnOnce(C) -> U>(self, fx: F) -> (A, B, U);
    fn map<U, F: FnOnce(A, B, C) -> U>(self, fx: F) -> U;
}

impl<A, B, C> TriMap<A, B, C> for (A, B, C) {
    fn map_left<U, F: FnOnce(A) -> U>(self, fx: F) -> (U, B, C) {
        ((fx)(self.0), self.1, self.2)
    }

    fn map_center<U, F: FnOnce(B) -> U>(self, fx: F) -> (A, U, C) {
        (self.0, (fx)(self.1), self.2)
    }

    fn map_right<U, F: FnOnce(C) -> U>(self, fx: F) -> (A, B, U) {
        (self.0, self.1, (fx)(self.2))
    }

    fn map<U, F: FnOnce(A, B, C) -> U>(self, fx: F) -> U {
        (fx)(self.0, self.1, self.2)
    }
}