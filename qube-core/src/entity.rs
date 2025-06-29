

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct EntityIndex(pub(crate) u64);

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Generation(u64);

impl Generation {
    pub const ZERO: Self = Self(0);

    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Entity {
    pub(crate) generation: Generation,
    pub(crate) index: EntityIndex
}

