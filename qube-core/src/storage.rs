use std::{
    alloc::{Allocator, Global, Layout},
    any::{TypeId, type_name},
    cell::{Ref, RefCell, RefMut},
    ptr::NonNull,
};

use crate::{Component, Entity, PluginName};

struct VecAny<A: Allocator = Global> {
    alloc: A,
    ty: TypeId,
    item_layout: Layout,
    ptr: NonNull<[u8]>,
    stride: usize,
    length: usize,
    capacity: usize,
}

unsafe impl<A: Allocator + Send> Send for VecAny<A> {}
unsafe impl<A: Allocator + Sync> Sync for VecAny<A> {}

impl<A: Allocator> VecAny<A> {
    const DEFAULT_CAPACITY: usize = 16;

    #[must_use]
    pub fn new_in(alloc: A, ty: TypeId, item_layout: Layout) -> Self {
        let (layout, stride) = item_layout.repeat(Self::DEFAULT_CAPACITY).unwrap();
        let ptr = alloc.allocate_zeroed(layout).unwrap();

        Self {
            alloc,
            ty,
            item_layout,
            ptr,
            stride,
            length: 0,
            capacity: Self::DEFAULT_CAPACITY,
        }
    }

    pub fn as_slice<T: 'static>(&self) -> &[T] {
        assert_eq!(self.ty, TypeId::of::<T>());

        unsafe { std::slice::from_raw_parts(self.ptr.cast().as_ptr(), self.length) }
    }

    pub fn as_slice_mut<T: 'static>(&mut self) -> &mut [T] {
        assert_eq!(self.ty, TypeId::of::<T>());

        unsafe { std::slice::from_raw_parts_mut(self.ptr.cast().as_ptr(), self.length) }
    }

    fn grow_to(&mut self, min_capacity: usize) {
        if min_capacity <= self.capacity {
            return;
        }

        let mut new_capacity = self.capacity;
        while min_capacity > new_capacity {
            new_capacity *= 2;
        }

        let (old_layout, _) = self.item_layout.repeat(self.capacity).unwrap();
        let (new_layout, _) = self.item_layout.repeat(new_capacity).unwrap();
        self.ptr = unsafe {
            self.alloc
                .grow_zeroed(self.ptr.cast(), old_layout, new_layout)
                .unwrap()
        };

        self.capacity = new_capacity;
    }

    pub fn push<T: 'static>(&mut self, item: T) {
        assert_eq!(self.ty, TypeId::of::<T>());

        self.grow_to(self.length + 1);
        unsafe {
            self.ptr
                .byte_offset((self.length * self.stride).try_into().unwrap())
                .cast()
                .write(item);
        }
        self.length += 1;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ComponentInfo {
    pub plugin: PluginName,
    pub name: &'static str,
    pub(crate) ty: TypeId,
    layout: Layout,
}

impl ComponentInfo {
    #[must_use]
    pub fn new<T: 'static>(plugin: PluginName) -> Self {
        Self {
            plugin,
            name: type_name::<T>(),
            ty: TypeId::of::<T>(),
            layout: Layout::new::<T>(),
        }
    }
}

pub struct ComponentSet<A: Allocator = Global> {
    pub(crate) info: ComponentInfo,
    entities: RefCell<Vec<Entity, A>>,
    components: RefCell<VecAny<A>>,
}

impl<A: Allocator + Copy> ComponentSet<A> {
    pub fn new(alloc: A, info: ComponentInfo) -> Self {
        Self {
            components: RefCell::new(VecAny::new_in(alloc, info.ty, info.layout)),
            info,
            entities: RefCell::new(Vec::new_in(alloc)),
        }
    }

    pub fn as_slice<T: Component + 'static>(&self) -> Ref<'_, [T]> {
        Ref::map(self.components.borrow(), |components| components.as_slice())
    }

    pub fn as_slice_mut<T: Component + 'static>(&self) -> RefMut<'_, [T]> {
        RefMut::map(self.components.borrow_mut(), |components| {
            components.as_slice_mut()
        })
    }

    pub fn attach<T: Component + 'static>(&self, entity: Entity, component: T) {
        assert_eq!(self.info.ty, TypeId::of::<T>());

        self.entities.borrow_mut().push(entity);
        self.components.borrow_mut().push(component);
    }
}
