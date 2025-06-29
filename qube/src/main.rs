use qube_core::{run, Manifest, PluginName, SetupError};

fn main() -> Result<(), SetupError> {
    run(&Manifest {
        required_plugins: vec![PluginName("qube_name")],
    })
}
