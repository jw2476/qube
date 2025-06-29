#![feature(vec_into_raw_parts)]
#![feature(alloc_layout_extra)]
#![feature(allocator_api)]
#![feature(path_add_extension)]

mod component;
mod entity;
mod plugin;
mod query;
mod storage;
mod world;

pub use component::Component;
pub use entity::Entity;
use libloading::library_filename;
pub use plugin::{Plugin, PluginName};
pub use query::Query;
pub use storage::ComponentInfo;
pub use world::World;

use std::{
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use log::debug;
use notify::{
    RecursiveMode, Watcher,
    event::{CreateKind},
};
use thiserror::Error;

pub use ctor::ctor;
pub use env_logger;
pub use log;
pub use qube_core_macros::*;

use crate::plugin::{load_plugins, reload_plugin};

#[derive(Error, Debug)]
pub enum SetupError {
    #[error("failed to find plugins")]
    IO(#[from] std::io::Error),
    #[error("failed to load one or more plugins")]
    Load(#[from] libloading::Error),
    #[error("failed to setup plugin watching")]
    Watcher(#[from] notify::Error),
}

pub struct Manifest {
    pub required_plugins: Vec<PluginName>,
}

pub fn run(manifest: Manifest) -> Result<(), SetupError> {
    if let Err(e) = env_logger::try_init() {
        eprintln!("Failed to set up logging on main thread: {e}");
    }

    let exe_path = std::env::current_exe()?;
    let exe_folder = exe_path.parent().unwrap();

    debug!("Loading plugins for {}", exe_path.display());

    let world = Arc::new(Mutex::new(World::default()));

    let plugins = manifest
        .required_plugins
        .iter()
        .map(|name| exe_folder.join(library_filename(&name.0)))
        .collect::<Vec<_>>();

    load_plugins(&mut world.lock().unwrap(), &plugins);

    let world_clone = world.clone();
    let mut watcher = notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
        let Ok(event) = result else {
            return;
        };

        match event.kind {
            notify::EventKind::Create(CreateKind::File) => event
                .paths
                .into_iter()
                .filter(|path| plugins.contains(path))
                .for_each(|path| reload_plugin(&mut world_clone.lock().unwrap(), path)),
            _ => {}
        }
    })?;

    watcher.watch(exe_folder, RecursiveMode::NonRecursive)?;

    loop {
        world.lock().unwrap().tick();
        thread::sleep(Duration::from_millis(10));
    }
}
