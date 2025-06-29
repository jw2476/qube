use std::{any::type_name, marker::PhantomData};

use log::debug;

use crate::{Component, World};

pub struct Query<'a, T: Component> {
    world: &'a World,
    phantom: PhantomData<T>,
}

impl<'a, T: Component + 'static> Query<'a, T> {
    pub fn new(world: &'a World) -> Self {
        Self {
            world,
            phantom: PhantomData,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        debug!("{}: {}", type_name::<T>(), self.world.components::<T>().len());
        self.world.components::<T>().iter()
    }
}
