use qube_core::{Component, Query, World, init, log::info, setup_plugin, system};

#[derive(Component, Clone, PartialEq, Eq, Debug)]
pub struct Name(String);

#[init]
pub fn spawn(world: &mut World) {
    println!("D");
    let entity = world.spawn();
    info!("Spawned: {entity:?}");
    world.attach(entity, Name("Bob".to_string()));
}

#[system]
pub fn log_all_names(query: Query<Name>) {
    query.iter().for_each(|name| info!("{name:?}"))
}

setup_plugin!();
