pub trait Component {}

#[allow(clippy::crate_in_macro_def)]
#[macro_export]
macro_rules! register_component {
    ($ident:ident, $ty:ty) => {
        impl qube_core::Component for $ty {}

        #[qube_core::ctor]
        fn $ident() {
            crate::COMPONENT_TYPES
                .lock()
                .unwrap()
                .push(qube_core::ComponentInfo::new::<$ty>(crate::PLUGIN_NAME))
        }
    };
}
