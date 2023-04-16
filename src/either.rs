#![allow(dead_code)]

pub(crate) struct Either<T, R> {
    preferred: Option<T>,
    other: Option<R>,
}

impl<T, R> Either<T, R> {
    pub fn preferred(self) -> Option<T> {
        self.preferred
    }

    pub fn other(self) -> Option<R> {
        self.other
    }

    pub fn pick(
        &self,
        pfn: impl FnOnce(&T) -> (),
        ofn: impl FnOnce(&R) -> (),
        none: impl FnOnce() -> (),
    ) {
        if let Some(preferred) = &self.preferred {
            pfn(preferred)
        } else if let Some(other) = &self.other {
            ofn(other)
        } else {
            none()
        }
    }
}
