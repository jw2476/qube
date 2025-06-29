use std::{
    cell::{Ref, RefMut},
    marker::PhantomData,
};

use crate::{Component, World};

pub struct Query<'w, T> {
    world: &'w World,
    phantom: PhantomData<T>,
}

impl<'w, T> Query<'w, T> {
    #[must_use]
    pub const fn new(world: &'w World) -> Self {
        Self {
            world,
            phantom: PhantomData,
        }
    }
}

struct QueryIter<'w, T> {
    slice: Option<Ref<'w, [T]>>,
}

impl<'w, T> QueryIter<'w, T> {
    #[must_use]
    const fn new(slice: Ref<'w, [T]>) -> Self {
        Self {
            slice: Some(slice),
        }
    }
}

impl<'w, T> Iterator for QueryIter<'w, T> {
    type Item = Ref<'w, T>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(slice) = self.slice.take()
            && !slice.is_empty()
        {
            let (item, slice) = Ref::map_split(slice, |slice| slice.split_first().unwrap());
            self.slice = Some(slice);
            Some(item)
        } else {
            None
        }
    }
}

struct QueryIterMut<'w, T> {
    slice: Option<RefMut<'w, [T]>>,
}

impl<'w, T> QueryIterMut<'w, T> {
    #[must_use]
    const fn new(slice: RefMut<'w, [T]>) -> Self {
        Self {
            slice: Some(slice),
        }
    }
}

impl<'w, T> Iterator for QueryIterMut<'w, T> {
    type Item = RefMut<'w, T>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(slice) = self.slice.take()
            && !slice.is_empty()
        {
            let (item, slice) = RefMut::map_split(slice, |slice| slice.split_first_mut().unwrap());
            self.slice = Some(slice);
            Some(item)
        } else {
            None
        }
    }
}

impl<T: Component + 'static> Query<'_, &T> {
    pub fn iter(&self) -> impl Iterator<Item = Ref<'_, T>> {
        QueryIter::new(self.world.components::<T>().as_slice())
    }
}

impl<T: Component + 'static> Query<'_, &mut T> {
    pub fn iter(&self) -> impl Iterator<Item = RefMut<'_, T>> {
        QueryIterMut::new(self.world.components::<T>().as_slice_mut())
    }
}
