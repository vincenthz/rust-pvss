use crate::crypto::Scalar;
use core::num::NonZeroU32;

// threshold need to >= 2
pub type Threshold = u32;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ShareId(NonZeroU32);

impl ShareId {
    pub fn first() -> Self {
        ShareId(NonZeroU32::new(1).unwrap())
    }

    pub fn next(self) -> Self {
        ShareId(self.0.checked_add(1).unwrap())
    }

    pub fn from_u32(v: u32) -> Option<Self> {
        NonZeroU32::new(v).map(ShareId)
    }

    pub fn to_scalar(self) -> Scalar {
        Scalar::from_u32(self.0.get())
    }

    pub fn as_index(self) -> usize {
        self.0.get() as usize - 1
    }
}

pub struct ShareIdsSequence(ShareId);

impl ShareIdsSequence {
    pub fn new() -> Self {
        Self(ShareId::first())
    }
}

impl Iterator for ShareIdsSequence {
    type Item = ShareId;

    fn next(&mut self) -> Option<Self::Item> {
        let c = self.0;
        self.0 = self.0.next();
        Some(c)
    }
}
