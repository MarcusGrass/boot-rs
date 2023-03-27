use alloc::string::String;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    App(String),
    Bail(String),
    Crypt(String),
    FindPartitions(String),
    MountPseudo(String),
    Mount(String),
    Cfg(String),
    Spawn(String),
    UnMount(String),
}
