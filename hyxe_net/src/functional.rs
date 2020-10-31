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