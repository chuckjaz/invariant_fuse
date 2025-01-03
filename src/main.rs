use std::{ffi::OsString, path::Path};

use clap::Parser;
use files_fuse::FilesFuse as FilesFuse;
use reqwest::Url;
use result::Result;
use env_logger::Env;
mod files_fuse;
mod result;

#[derive(Debug, Parser)]
#[command(name = "inv-fuse")]
#[command(author = "Chuck Jazdzewski (chuckjaz@gmail.com)")]
#[command(version = "0.1.0")]
#[command(about = "A FUSE to mount an invariant file system locally")]
pub struct FuseCommand {
    /// The URL of the file system host. It is highly recommended that this be a local service
    /// inaccessible outside the local machine.
    url: Url,

    /// The location to mount the directory
    path: OsString,
}

fn main() -> Result<()> {
    let env = Env::new().filter("INVARIANT_LOG");
    env_logger::try_init_from_env(env)?;
    let config = FuseCommand::parse();
    let url = config.url;
    let path_text = config.path;
    println!("Starting FUSE: host: {url}, path: {path_text:?}");
    let path = Path::new(&path_text);
    start_fuse(url, path)?;
    Ok(())
}

fn start_fuse(url: Url, path: &Path) -> Result<()>{
    let filesystem = FilesFuse::new(url.clone());
    let id = filesystem.ping();
    match id {
        Err(e) => {
            println!("Could not connect to server at {url}, {e}");
            Err(e)
        },
        Ok(_) =>  {
            fuser::mount2(filesystem, path, &[])?;
            Ok(())
        }
    }
}
