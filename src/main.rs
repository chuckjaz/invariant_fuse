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
#[command(version = "0.2.1")]
#[command(about = "A FUSE to mount an invariant file system locally")]
pub struct FuseCommand {
    /// The URL of the file system host. It is highly recommended that this be a local service
    /// inaccessible outside the local machine.
    url: Url,

    /// The location to mount the directory
    path: OsString,

    /// The address or content link
    #[arg(long, value_parser = clap::value_parser!(String))]
    content_link: Option<String>,

    /// The inode number to use for the root directory
    #[arg(long, value_parser = clap::value_parser!(u64))]
    root: Option<u64>,
}

fn main() -> Result<()> {
    let env = Env::new().filter("INVARIANT_LOG");
    env_logger::try_init_from_env(env)?;
    let config = FuseCommand::parse();
    let url = config.url;
    let path_text = config.path;
    let content_link = config.content_link;
    let root = config.root;

    if root.is_some() && content_link.is_some() {
        Err("Cannot specify both root inode and content link")?;
    }
    if root.is_none() && content_link.is_none() {
        Err("Must specify either root inode or content link")?;
    }
    println!("Starting FUSE: host: {url}, path: {path_text:?}");
    let path = Path::new(&path_text);
    start_fuse(url, path, &content_link, &root)?;

    Ok(())
}

fn start_fuse(url: Url, path: &Path, content_link: &Option<String>, root: &Option<u64>) -> Result<()>{
    let root = root.unwrap_or(1);
    let filesystem = if let Some(link) = content_link {
        FilesFuse::mount(url.clone(), link.clone())?
    } else {
        FilesFuse::create(url.clone(), root)
    };
    fuser::mount2(filesystem, path, &[])?;

    Ok(())
}
