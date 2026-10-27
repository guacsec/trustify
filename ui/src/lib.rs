//! Embedded console assets for the native Trustify server.

#[cfg(all(feature = "embed", not(target_arch = "wasm32")))]
mod embedded {
    use static_files::Resource;
    use std::collections::HashMap;

    include!(concat!(env!("OUT_DIR"), "/generated.rs"));

    /// The server mount used for console assets and client-side navigation.
    #[derive(Clone, Copy)]
    pub enum Mount {
        /// The console is the only embedded UI.
        Root,
        /// The existing UI occupies the root path.
        Console,
    }

    impl Mount {
        /// Absolute base path, including its trailing slash.
        pub const fn path(self) -> &'static str {
            match self {
                Self::Root => "/",
                Self::Console => "/console/",
            }
        }
    }

    /// Load embedded assets with an index document matching the server mount.
    pub fn resources(mount: Mount) -> HashMap<&'static str, Resource> {
        let mut resources = generate();
        if let Some(index) = resources.get_mut("index.html") {
            index.data = match mount {
                Mount::Root => include_bytes!(concat!(env!("OUT_DIR"), "/index-root.html")),
                Mount::Console => include_bytes!(concat!(env!("OUT_DIR"), "/index-console.html")),
            };
        }
        resources
    }
}

#[cfg(all(feature = "embed", not(target_arch = "wasm32")))]
pub use embedded::{Mount, resources};
