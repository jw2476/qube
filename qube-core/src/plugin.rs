use std::{
    ops::Deref,
    path::{Path, PathBuf},
};

use libloading::{Library, Symbol};
use thiserror::Error;

use crate::{ComponentInfo, World};

#[cfg(target_os = "linux")]
const DYNAMIC_LIBRARY_EXTENSION: &str = "so";

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct PluginName(pub &'static str);

#[derive(Debug)]
pub struct Plugin {
    pub(crate) name: PluginName,
    pub(crate) components: Vec<ComponentInfo>,
    pub(crate) initialisers: Vec<fn(&mut World)>,
    pub(crate) systems: Vec<fn(&World)>,
}

impl Plugin {
    #[must_use]
    pub const fn new(name: PluginName) -> Self {
        Self {
            name,
            components: Vec::new(),
            initialisers: Vec::new(),
            systems: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_components(mut self, components: &[ComponentInfo]) -> Self {
        self.components.extend_from_slice(components);
        self
    }

    #[must_use]
    pub fn with_initialisers(mut self, initialisers: &[fn(&mut World)]) -> Self {
        self.initialisers.extend_from_slice(initialisers);
        self
    }

    #[must_use]
    pub fn with_systems(mut self, systems: &[fn(&World)]) -> Self {
        self.systems.extend_from_slice(systems);
        self
    }
}

pub struct LoadedPlugin {
    plugin: Plugin,
    pub(crate) path: PathBuf,
    iteration: usize,
    _library: Library,
}

impl Deref for LoadedPlugin {
    type Target = Plugin;

    fn deref(&self) -> &Self::Target {
        &self.plugin
    }
}

impl LoadedPlugin {
    const fn new(plugin: Plugin, path: PathBuf, iteration: usize, library: Library) -> Self {
        Self {
            plugin,
            path,
            iteration,
            _library: library,
        }
    }

    pub(crate) fn reload(&self) -> Result<Self, LoadPluginError> {
        std::fs::remove_file(self.path.with_added_extension(self.iteration.to_string()))?;
        unsafe { load_plugin(&self.path, self.iteration + 1) }
    }
}

#[derive(Error, Debug)]
pub enum LoadPluginError {
    #[error("failed to load the dynamic library.")]
    Load(#[from] libloading::Error),
    #[error("failed to copy the dynamic library, or failed to remove the old copy")]
    Io(#[from] std::io::Error),
}

unsafe fn load_plugin<P: AsRef<Path>>(
    path: P,
    iteration: usize,
) -> Result<LoadedPlugin, LoadPluginError> {
    let path = path.as_ref();
    let iteration_path = path.with_added_extension(iteration.to_string());
    std::fs::copy(path, &iteration_path)?;

    let library = unsafe { Library::new(iteration_path)? };
    let setup = unsafe { library.get::<Symbol<extern "C" fn() -> Plugin>>(b"setup")? };
    let plugin = setup();

    Ok(LoadedPlugin::new(
        plugin,
        path.to_owned(),
        iteration,
        library,
    ))
}

pub fn load_plugins(world: &mut World, paths: &[PathBuf]) {
    paths
        .iter()
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext == DYNAMIC_LIBRARY_EXTENSION)
        })
        .for_each(|path| world.register(unsafe { load_plugin(path, 0).unwrap() }));
}

pub fn reload_plugin<P: AsRef<Path>>(world: &mut World, path: P) {
    let plugin = world.unregister_by_path(path.as_ref());
    world.register(plugin.reload().unwrap());
}

#[macro_export]
macro_rules! setup_plugin {
    () => {
        pub static PLUGIN_NAME: qube_core::PluginName =
            qube_core::PluginName(env!("CARGO_CRATE_NAME"));

        pub(crate) static COMPONENT_TYPES: std::sync::Mutex<Vec<qube_core::ComponentInfo>> =
            std::sync::Mutex::new(Vec::new());

        pub(crate) static INITIALISERS: std::sync::Mutex<Vec<fn(&mut qube_core::World)>> =
            std::sync::Mutex::new(Vec::new());

        pub(crate) static SYSTEMS: std::sync::Mutex<Vec<fn(&qube_core::World)>> =
            std::sync::Mutex::new(Vec::new());

        #[unsafe(no_mangle)]
        pub extern "C" fn setup() -> qube_core::Plugin {
            if let Err(e) = qube_core::env_logger::try_init() {
                qube_core::log::warn!("{e}");
            }

            qube_core::Plugin::new(PLUGIN_NAME)
                .with_components(&COMPONENT_TYPES.lock().unwrap())
                .with_initialisers(&INITIALISERS.lock().unwrap())
                .with_systems(&SYSTEMS.lock().unwrap())
        }
    };
}

#[macro_export]
#[allow(clippy::crate_in_macro_def)]
macro_rules! register_initialiser {
    ($ident:ident, $initialiser:ident) => {
        #[qube_core::ctor]
        fn $ident() {
            crate::INITIALISERS.lock().unwrap().push($initialiser)
        }
    };
}

#[macro_export]
#[allow(clippy::crate_in_macro_def)]
macro_rules! register_system {
    ($ident:ident, $system:ident) => {
        #[qube_core::ctor]
        fn $ident() {
            fn inner(world: &qube_core::World) {
                $system(qube_core::Query::new(world))
            }

            crate::SYSTEMS.lock().unwrap().push(inner)
        }
    };
}
