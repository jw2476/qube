use std::{
    alloc::Global,
    any::{TypeId, type_name},
    path::Path,
};

use log::debug;

use crate::{
    Component, Entity,
    entity::{EntityIndex, Generation},
    plugin::LoadedPlugin,
    storage::ComponentSet,
};

#[derive(Default)]
pub struct World {
    entities: Vec<Generation>,
    components: Vec<ComponentSet>,
    plugins: Vec<LoadedPlugin>,
}

impl World {
    pub fn spawn(&mut self) -> Entity {
        let generation = Generation::ZERO;

        self.entities.push(Generation::ZERO);
        Entity {
            generation,
            index: EntityIndex(self.entities.len() as u64 - 1),
        }
    }

    pub(crate) fn tick(&self) {
        self.plugins
            .iter()
            .flat_map(|plugin| &plugin.systems)
            .for_each(|system| system(self));
    }

    pub(crate) fn components<T: Component + 'static>(&self) -> &ComponentSet {
        self.components
            .iter()
            .find(|set| set.info.ty == TypeId::of::<T>())
            .unwrap_or_else(|| {
                panic!(
                    "Tried to use unregistered component type {}",
                    type_name::<T>()
                )
            })
    }

    pub(crate) fn components_mut<T: Component + 'static>(&mut self) -> &mut ComponentSet {
        self.components
            .iter_mut()
            .find(|set| set.info.ty == TypeId::of::<T>())
            .unwrap_or_else(|| {
                panic!(
                    "Tried to use unregistered component type {}",
                    type_name::<T>()
                )
            })
    }

    pub fn attach<T: Component + 'static>(&mut self, entity: Entity, component: T) {
        assert_eq!(
            entity.generation,
            self.entities[usize::try_from(entity.index.0).unwrap()]
        );
        self.components_mut::<T>().attach(entity, component);
    }

    pub(crate) fn register(&mut self, plugin: LoadedPlugin) {
        plugin.components.iter().copied().for_each(|info| {
            debug!("Registered: {}", info.name);
            self.components
                .push(ComponentSet::new(Global, info));
        });

        plugin
            .initialisers
            .iter()
            .for_each(|initialiser| initialiser(self));

        self.plugins.push(plugin);
    }

    pub(crate) fn unregister_by_path(&mut self, path: &Path) -> LoadedPlugin {
        let index = self
            .plugins
            .iter()
            .position(|plugin| plugin.path == path)
            .expect("Couldn't find plugin to unregister");

        let plugin = self.plugins.remove(index);

        plugin
            .components
            .iter()
            .for_each(|info| debug!("Unregistered: {}", info.name));
        self.components.retain(|set| set.info.plugin != plugin.name);

        debug!("Unloaded: {}", plugin.name.0);
        plugin
    }
}
