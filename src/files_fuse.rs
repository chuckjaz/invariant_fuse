use bytes::Bytes;
use fuser::{FileAttr, FileType, Filesystem};
use reqwest::{blocking::{Body, Client}, Url};
use libc::{c_int, ENOENT, ENOSYS};
use log::debug;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::{atomic::AtomicUsize, Arc, Mutex}, time::{Duration, SystemTime, UNIX_EPOCH}};
use crate::result::Result;
use threadpool::ThreadPool;

#[derive(Clone)]
struct FilesServer {
    /// The url of the files server
    url: Url,

    /// The node mounted as root. This must be 1 for Filesystem APIs so it must be mapped to 1 for
    /// Filesystem APIs
    root: u64,
}


impl FilesServer {
    fn info(&self, node: u64) -> Result<ContentInformation> {
        debug!("FileServer::info: node: {node}");
        let in_node = self.node_in(node);
        let path = format!("files/info/{in_node}");
        let url = self.url.join(&path)?;
        debug!("FileFuse::info url={url}");
        let client = Client::new();
        let text = client.get(url).send()?.text()?;
        let mut content_info = serde_json::from_str::<ContentInformation>(&text)?;
        debug!("FileServer::info: return");
        self.out_info(&mut content_info);
        Ok(content_info)
    }

    fn setattr(&self, node: u64, attr: &EntryAttributes) -> Result<ContentInformation> {
        let in_node = self.node_in(node);
        let path = format!("files/attributes/{in_node}");
        let url = self.url.join(&path)?;
        let attr_text = serde_json::to_string(attr)?;
        let client = Client::new();
        let text = client.post(url).body(attr_text).send()?.text()?;
        let content_info = serde_json::from_str::<ContentInformation>(&text)?;
        Ok(content_info)
    }

    fn setattr_spec(
        &self,
        node: u64,
        mode: Option<u32>,
        mtime: Option<fuser::TimeOrNow>,
        ctime: Option<std::time::SystemTime>,
        size: Option<u64>,
    ) -> Result<ContentInformation> {
        let in_node = self.node_in(node);
        let attr = EntryAttributes::new(mode, mtime, ctime, size)?;
        self.setattr(in_node, &attr)
    }

    fn create_file(&self, parent: u64, name: &str) -> Result<ContentInformation> {
        let in_parent = self.node_in(parent);
        let path = format!("files/{in_parent}/{name}");
        let url = self.url.join(&path)?;
        let client = Client::new();
        let text = client.put(url).send()?.text()?;
        let content_info = serde_json::from_str::<ContentInformation>(&text)?;
        Ok(content_info)
    }

    fn create_directory(&self, parent: u64, name: &str) -> Result<ContentInformation> {
        let in_parent = self.node_in(parent);
        let path = format!("files/{in_parent}/{name}");
        let mut url = self.url.join(&path)?;
        url.set_query(Some("kind=Directory"));
        let client = Client::new();
        let text = client.put(url).send()?.text()?;
        let content_info = serde_json::from_str::<ContentInformation>(&text)?;
        Ok(content_info)
    }

    fn create_symbolic_link(&self, parent: u64, name: &str, target: &str) -> Result<ContentInformation> {
        let in_parent = self.node_in(parent);
        let path = format!("files/{in_parent}/{name}");
        let mut url = self.url.join(&path)?;
        let target_param = format!("target={target}");
        url.set_query(Some("kind=SymbolicLink"));
        url.set_query(Some(&target_param));
        let client = Client::new();
        let text = client.put(url).send()?.text()?;
        let content_info = serde_json::from_str::<ContentInformation>(&text)?;
        Ok(content_info)
    }

    fn remove_node(&self, parent: u64, name: &str) -> Result<bool> {
        let in_parent = self.node_in(parent);
        let path = format!("files/remove/{in_parent}/{name}");
        let url = self.url.join(&path)?;
        let client = Client::new();
        let text = client.post(url).send()?.text()?;

        Ok(text.parse()?)
    }

    fn rename_node(&self, parent: u64, name: &str, new_parent: u64, new_name: &str) -> Result<bool> {
        let in_parent = self.node_in(parent);
        let in_new_parent = self.node_in(new_parent);
        let path = format!("files/rename/{in_parent}/{name}");
        let mut url = self.url.join(&path)?;
        let new_parent = format!("newParent={in_new_parent}");
        let new_name = format!("newName={new_name}");
        url.set_query(Some(&new_parent));
        url.set_query(Some(&new_name));
        let client = Client::new();
        let response = client.post(url).send()?;

        Ok(response.status() == 200)
    }

    fn link_node(&self, parent: u64, node: u64, name: &str) -> Result<bool> {
        let in_parent = self.node_in(parent);
        let in_node = self.node_in(node);
        let path = format!("files/link/{in_parent}/{name}");
        let mut url = self.url.join(&path)?;
        let node = format!("node={in_node}");
        url.set_query(Some(&node));
        let client = Client::new();
        let response = client.post(url).send()?;
        Ok(response.status() == 200)
    }

    fn link_info(&self, parent: u64, node: u64, name: &str) -> Result<Option<ContentInformation>> {
        let in_parent = self.node_in(parent);
        let in_node = self.node_in(node);
        let result = self.link_node(in_parent, in_node, name)?;
        if result {
            Ok(Some(self.info(node)?))
        } else {
            Ok(None)
        }
    }

    fn read_node(&self, node: u64, offset: u64, length: u64) -> Result<Bytes> {
        let in_node = self.node_in(node);
        let path = format!("files/{in_node}");
        let mut url = self.url.join(&path)?;
        let offset_option = format!("offset={offset}");
        let length_option = format!("length={length}");
        url.set_query(Some(&offset_option));
        url.set_query(Some(&length_option));
        let client = Client::new();
        let response = client.get(url).send()?;
        Ok(response.bytes()?)
    }

    fn write_node(&self, node: u64, offset: u64, data: &[u8]) -> Result<u64> {
        debug!("FileServer::write_node: node: {node}, offset: {offset}");
        let in_node = self.node_in(node);
        let path = format!("files/{in_node}");
        let mut url = self.url.join(&path)?;
        let offset_option = format!("offset={offset}");
        url.set_query(Some(&offset_option));
        let bytes = Bytes::copy_from_slice(data);
        let body = Body::from(bytes);
        let client = Client::new();
        let response = client.post(url).body(body).send()?;
        let text = response.text()?;
        let written: u64 = text.parse()?;
        debug!("FileServer::write_node return: node: {node} -> {written}");
        Ok(written)
    }

    fn read_directory(&self, node: u64, offset: u64) -> Result<Vec<FileDirectoryEntry>> {
        let in_node = self.node_in(node);
        let path = format!("files/directory/{in_node}");
        let mut url = self.url.join(&path)?;
        if offset > 0 {
            let offset_option = format!("offset={offset}");
            url.set_query(Some(&offset_option));
        }
        let client = Client::new();
        let text = client.get(url).send()?.text()?;
        Ok(serde_json::from_str(&text)?)
    }

    fn sync(&self) -> Result<()> {
        let url = self.url.join("/files/sync")?;
        let client = Client::new();
        client.put(url).send()?;
        Ok(())
    }

    fn out_info(&self, info: &mut ContentInformation) {
        if info.node == self.root {
            info.node = 1
        }
    }

    fn node_in(&self, node: u64) -> u64 {
        if node == 1 {
            self.root
        } else {
            node
        }
    }
}

struct DirectoryEntryCache {
    map: HashMap<String, u64>,
    order: Vec<String>,
}

impl DirectoryEntryCache {
    fn new() -> Arc<Mutex<DirectoryEntryCache>> {
        Arc::new(Mutex::new(Self { map: HashMap::new(), order: Vec::new() }))
    }

    fn get(&self, name: &String) -> Option<&u64> {
        self.map.get(name)
    }

    fn insert(&mut self, name: &String, node: u64) {
        let previous = self.map.insert(name.clone(), node);
        if previous.is_none() {
            self.order.push(name.clone());
        }
    }

    fn each<F>(&self, mut f: F) where F: FnMut(i64, &String, u64) -> bool {
        let mut index = 0;
        for name in self.order.iter() {
            let node = self.map.get(name).unwrap();
            if !f(index, name, *node) { break; }
            index += 1;
        }
    }
}

struct InfoCache {
    info_map: Mutex<HashMap<u64, ContentInformation>>,
    directory_entries: Arc<Mutex<HashMap<u64, Arc<Mutex<DirectoryEntryCache>>>>>
}

impl InfoCache {
    fn new() -> Arc<InfoCache> {
        Arc::new(InfoCache {
            info_map: Mutex::new(HashMap::new()),
            directory_entries: Arc::new(Mutex::new(HashMap::new()))
        })
    }

   fn ensure_directory(
        &self,
        parent: u64,
        server: &FilesServer,
    ) -> Option<Arc<Mutex<DirectoryEntryCache>>>  {
        debug!("InfoCache:ensure_directory: {parent}");
        let mut directory_entries = self.directory_entries.lock().unwrap();
        let mut info_map = self.info_map.lock().unwrap();
        if let Some(entries) = directory_entries.get(&parent) {
            debug!("InfoCache:ensure_directory: {parent} found");
            Some((*entries).clone())
        } else {
            debug!("InfoCache:ensure_directory: {parent} not found, reading from server");
            let new_entries = DirectoryEntryCache::new();
            match server.read_directory(parent, 0) {
                Ok(entries) => {
                    let mut new_entries_locked = new_entries.lock().unwrap();
                    for entry in entries {
                        info_map.insert(entry.info.node, entry.info.clone());
                        new_entries_locked.insert(&entry.name, entry.info.node);
                        debug!("InfoCache:ensure_directory: received: {parent} -> {} {}", entry.info.node, entry.name);
                    }
                    directory_entries.insert(parent, new_entries.clone());
                    debug!("InfoCache:ensure_directory: {parent} read complete");
                    Some(new_entries.clone())
                }
                Err(_) => {
                    debug!("InfoCache:ensure_directory: {parent} READ FAILED");
                    None
                }
            }
        }
    }

    fn add_info(
        &self,
        parent: u64,
        name: &String,
        info: &ContentInformation
    ) {
        let directory_entries = self.directory_entries.lock().unwrap();
        let mut info_map = self.info_map.lock().unwrap();
        info_map.insert(info.node, info.clone());
        match directory_entries.get(&parent) {
            Some(entries) => {
                let mut e = entries.lock().unwrap();
                e.insert(name, info.node);
            }
            None => {}
        }
    }

    fn find_info(
        &self,
        node: u64,
        server: &FilesServer
    ) -> Option<ContentInformation> {
        debug!("InfoCache:find_node: {node}");
        let mut info_map = self.info_map.lock().unwrap();
        match info_map.get(&node) {
            Some(info) => Some(info.clone()),
            None => {
                match server.info(node) {
                    Ok(info) => {
                        info_map.insert(node, info.clone());
                        Some(info)
                    }
                    Err(_) => None
                }
            }
        }
    }

    fn invalidate_node(
        &self,
        node: u64
    ) {
        debug!("InfoCache:invalidate_node: {node}");
        let mut directory_entries = self.directory_entries.lock().unwrap();
        let mut info_map = self.info_map.lock().unwrap();
        info_map.remove(&node);
        directory_entries.remove(&node);

    }

    fn update_node(
        &self,
        node: u64,
        info: &ContentInformation
    ) {
        debug!("InfoCache:update_node: {node}");
        let mut info_map = self.info_map.lock().unwrap();
        info_map.insert(node, info.clone());
    }
}

/// A file system implementation that uses the Files Server API
pub struct FilesFuse {
    /// The file server
    server: FilesServer,

    /// Thread pool to use
    thread_pool: ThreadPool,

    /// Directory info cache
    info_cache: Arc<InfoCache>,
}

static RUN_ID: AtomicUsize = AtomicUsize::new(0);

impl FilesFuse {
    pub fn create(url: Url, root: u64) -> Self {
        Self {
            server: FilesServer { url, root },
            thread_pool: ThreadPool::new(8),
            info_cache: InfoCache::new(),
        }
    }

    pub fn mount(url: Url, content_link: String) -> Result<Self> {
        let path = format!("files/mount");
        let mount_url = url.clone().join(&path)?;
        let body = Body::from(content_link);
        let client = Client::new();
        let text = client.post(mount_url.clone()).body(body).send()?.text()?;
        debug!("mount response: {text}");
        let root = text.parse::<u64>()?;
        Ok(Self {
            server: FilesServer { url, root },
            thread_pool: ThreadPool::new(8),
            info_cache: InfoCache::new(),
        })
    }

    fn run<F: FnOnce() + Send + 'static>(&mut self, f: F) {
        self.thread_pool.execute(move || {
            let id = RUN_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let thread_id = std::thread::current().id();
            debug!("FileFuse::run start: {id}, thread: {thread_id:?}");
            f();
            debug!("FileFuse::run done: {id}, thread: {thread_id:?}");
        });
    }
}


impl Filesystem for FilesFuse {
    fn init(&mut self, _req: &fuser::Request<'_>, _config: &mut fuser::KernelConfig) -> std::result::Result<(), c_int> {                                                                                                                                                                                                    // let server = self.server.clone();
        Ok(())
    }

    fn destroy(&mut self) {}

    fn lookup(&mut self, _req: &fuser::Request<'_>, parent: u64, name: &std::ffi::OsStr, reply: fuser::ReplyEntry) {
        debug!("lookup(parent: {parent}, name {name:?})");
        let server = self.server.clone();
        let uid = _req.uid();
        let gid = _req.gid();
        let name_str: String = name.to_string_lossy().into();
        let info_cache = self.info_cache.clone();
        self.run(move || {
            match info_cache.ensure_directory(parent, &server) {
                Some(directory) => {
                    let dir = directory.lock().unwrap();
                    match dir.get(&name_str) {
                        Some(node) => {
                            match info_cache.find_info(*node, &server) {
                                Some(info) => {
                                    let attr = info.to_attr(uid, gid);
                                    reply.entry(&SLOT_TTL, &attr, 1)
                                }
                                None => reply.error(ENOENT)
                            }
                        },
                        None => reply.error(ENOENT),
                    }
                }
                None => reply.error(ENOENT)
            }
        });
    }

    fn forget(&mut self, _req: &fuser::Request<'_>, _ino: u64, _nlookup: u64) {}

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, fh: Option<u64>, reply: fuser::ReplyAttr) {
        debug!("getattr(ino: {ino}, fh: {fh:?}");
        let server = self.server.clone();
        let uid = _req.uid();
        let gid = _req.gid();
        let info_cache = self.info_cache.clone();
        self.run(move || {
            match info_cache.find_info(ino, &server) {
                Some(info) => {
                    let attr = info.to_attr(uid, gid);
                    reply.attr(&SLOT_TTL, &attr)
                },
                None => {
                    reply.error(ENOENT)
                },
            }
        })
    }

    fn setattr(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        fh: Option<u64>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        flags: Option<u32>,
        reply: fuser::ReplyAttr,
    ) {
        debug!("setattr(ino: {ino}, mode: {mode:?}, uid: {uid:?}, gid: {gid:?}, size: {size:?}, fh: {fh:?}, flags: {flags:?})");
        let server = self.server.clone();
        let effective_uid = _req.uid();
        let effective_gid = _req.gid();
        let info_cache = self.info_cache.clone();
        self.run(move || {
            match server.setattr_spec(ino, mode, _mtime, _ctime, size) {
                Ok(info) => {
                    let attr = info.to_attr(effective_uid, effective_gid);
                    info_cache.update_node(ino, &info);
                    reply.attr(&SLOT_TTL, &attr)
                },
                Err(_) => reply.error(ENOENT)
            }
        })
    }

    fn readlink(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyData) {
        debug!("readlink(ino: {:#x?})", ino);
        let server = self.server.clone();
        let info_cache = self.info_cache.clone();
        match info_cache.find_info(ino, &server) {
            Some(info) => {
                match info.target {
                    Some(target) => reply.data(target.as_bytes()),
                    None => reply.error(ENOENT),
                }
            }
            None => reply.error(ENOENT)
        }
    }

    fn mknod(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: fuser::ReplyEntry,
    ) {
        debug!("mknod(parent: {parent}, name: {name:?}, mode: {mode}, umask: {umask}, rdev: {rdev})");
        let server = self.server.clone();
        let uid = _req.uid();
        let gid = _req.gid();
        let name_str: String = name.to_string_lossy().into();
        let info_cache = self.info_cache.clone();
        self.run(move || {
            match server.create_file(parent, &name_str) {
                Ok(info) => {
                    let attr = info.to_attr(uid, gid);
                    info_cache.add_info(parent, &name_str, &info);
                    reply.entry(&SLOT_TTL, &attr, 1)
                },
                Err(_) => reply.error(ENOSYS),
            }
        });
    }

    fn mkdir(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        mode: u32,
        umask: u32,
        reply: fuser::ReplyEntry,
    ) {
        debug!("mkdir(parent: {parent}, name: {name:?}, mode: {mode}, umask: {umask})");
        let server = self.server.clone();
        let name_str: String = name.to_string_lossy().into();
        let uid = _req.uid();
        let gid = _req.gid();
        let info_cache = self.info_cache.clone();
        self.run(move || {
            match server.create_directory(parent, &name_str) {
                Ok(info) => {
                    let attr = info.to_attr(uid, gid);
                    info_cache.add_info(parent, &name_str, &info);
                    reply.entry(&SLOT_TTL, &attr, 1)
                },
                Err(_) => reply.error(ENOSYS),
            }
        })
    }

    fn unlink(&mut self, _req: &fuser::Request<'_>, parent: u64, name: &std::ffi::OsStr, reply: fuser::ReplyEmpty) {
        debug!("unlink(parent: {parent}, name: {name:?})");
        let server = self.server.clone();
        let name_str: String = name.to_string_lossy().into();
        let info_cache = self.info_cache.clone();
        self.run(move || {
            match server.remove_node(parent, &name_str) {
                Ok(result) => if result {
                    info_cache.invalidate_node(parent);
                    reply.ok()
                } else {
                    reply.error(ENOENT)
                }
                Err(_) => reply.error(ENOSYS),
            }
        })
    }

    fn rmdir(&mut self, _req: &fuser::Request<'_>, parent: u64, name: &std::ffi::OsStr, reply: fuser::ReplyEmpty) {
        debug!("rmdir(parent: {parent}, name: {name:?})");
        let server = self.server.clone();
        let name_str: String = name.to_string_lossy().into();
        let info_cache = self.info_cache.clone();
        self.run(move || {
            match server.remove_node(parent, &name_str) {
                Ok(result) => if result {
                    info_cache.invalidate_node(parent);
                    reply.ok()
                } else {
                    reply.error(ENOENT)
                }
                Err(_) => reply.error(ENOSYS),
            }
        })
    }

    fn symlink(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        link_name: &std::ffi::OsStr,
        target: &std::path::Path,
        reply: fuser::ReplyEntry,
    ) {
        let server = self.server.clone();
        let name_str: String = link_name.to_string_lossy().into();
        let target: String = target.to_str().unwrap().into();
        let uid = _req.uid();
        let gid = _req.gid();
        let info_cache = self.info_cache.clone();
        self.run(move || {
            match server.create_symbolic_link(parent, &name_str, &target) {
                Ok(info) => {
                    let attr = info.to_attr(uid, gid);
                    info_cache.add_info(parent, &name_str, &info);
                    reply.entry(&SLOT_TTL, &attr, 1)
                },
                Err(_) => reply.error(ENOENT),
            }
        });
    }

    fn rename(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        newparent: u64,
        newname: &std::ffi::OsStr,
        flags: u32,
        reply: fuser::ReplyEmpty,
    ) {
        debug!("rename(parent: {parent}, name: {name:?}, newparent: {newparent},  newname: {newname:?}, flags: {flags})");
        let server = self.server.clone();
        let name_str: String = name.to_string_lossy().into();
        let new_name_str: String = newname.to_string_lossy().into();
        let info_cache = self.info_cache.clone();

        self.run(move || {
            match server.rename_node(parent, &name_str, newparent, &new_name_str) {
                Ok(result) => if result {
                    info_cache.invalidate_node(parent);
                    info_cache.invalidate_node(newparent);
                    reply.ok()
                } else {
                    reply.error(ENOENT)
                }
                Err(_) => reply.error(ENOSYS),
            }
        })
    }

    fn link(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        newparent: u64,
        newname: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        debug!("link(ino: {ino}, newparent: {newparent}, newname: {newname:?})");
        let server = self.server.clone();
        let new_name_str: String = newname.to_string_lossy().into();
        let uid = _req.uid();
        let gid = _req.gid();
        let info_cache = self.info_cache.clone();
        self.run(move || {
            match server.link_info(newparent, ino, &new_name_str) {
                Ok(result) => match result {
                    Some(info) => {
                        let attr = info.to_attr(uid, gid);
                        info_cache.invalidate_node(newparent);
                        reply.entry(&SLOT_TTL, &attr, 1);
                    }
                    None => reply.error(ENOENT),
                },
                Err(_) => reply.error(ENOSYS),
            }
        })
    }

    fn open(&mut self, _req: &fuser::Request<'_>, _ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        reply.opened(0, 0);
    }

    fn read(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        flags: i32,
        lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        debug!("read(ino: {ino}, fh: {fh}, offset: {offset}, size: {size}, flags: {flags}, lock_owner: {lock_owner:?})");
        let server = self.server.clone();
        let effective_offset: u64 = offset.try_into().unwrap();
        let effective_size: u64 = size.into();
        self.run(move || {
            match server.read_node(ino, effective_offset, effective_size) {
                Ok(bytes) => {
                    reply.data(&bytes[..]);
                }
                Err(_) => reply.error(ENOSYS),
            }
        })
    }

    fn write(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        write_flags: u32,
        flags: i32,
        lock_owner: Option<u64>,
        reply: fuser::ReplyWrite,
    ) {
        debug!("write(ino: {ino}, fh: {fh}, offset: {offset}, data.len(): {}, write_flags: {write_flags}, flags: {flags}, lock_owner: {lock_owner:?})",
            data.len(),
        );
        let server = self.server.clone();
        let effective_offset: u64 = offset.try_into().unwrap();
        let data_buf = Vec::from(data);
        let info_cache = self.info_cache.clone();
        self.run(move || {
            match server.write_node(ino, effective_offset, &data_buf) {
                Ok(written) => {
                    info_cache.invalidate_node(ino);
                    reply.written(written.try_into().unwrap())
                },
                Err(_) => reply.error(ENOSYS),
            }
        })
    }

    fn flush(&mut self, _req: &fuser::Request<'_>, ino: u64, fh: u64, lock_owner: u64, reply: fuser::ReplyEmpty) {
        debug!("flush(ino: {ino}, fh: {fh}, lock_owner: {lock_owner:?})");
        let server = self.server.clone();
        self.run(move || {
            match server.sync() {
                Ok(_) => reply.ok(),
                Err(_) => reply.error(ENOSYS),
            }
        })
    }

    fn release(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsync(&mut self, _req: &fuser::Request<'_>, ino: u64, fh: u64, datasync: bool, reply: fuser::ReplyEmpty) {
        debug!("fsync(ino: {ino}, fh: {fh}, datasync: {datasync})");
        let server = self.server.clone();
        self.run(move || {
            match server.sync() {
                Ok(_) => reply.ok(),
                Err(_) => reply.error(ENOSYS),
            }
        })
    }

    fn opendir(&mut self, _req: &fuser::Request<'_>, _ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        reply.opened(0, 0);
    }

    fn readdir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        mut reply: fuser::ReplyDirectory,
    ) {
        debug!("readdir(ino: {ino}, fh: {fh}, offset: {offset})");
        let server = self.server.clone();
        let effective_offset = offset.try_into().unwrap();
        let info_cache = self.info_cache.clone();
        self.run(move || {
            match info_cache.ensure_directory(ino, &server) {
                Some(directory_entries) => {
                    let entries = directory_entries.lock().unwrap();
                    entries.each(|index, name, node| {
                        if index >= effective_offset {
                            match info_cache.find_info(node, &server) {
                                Some(info) => {
                                    let kind = if info.kind == ContentKind::Directory {
                                        FileType::Directory
                                    } else {
                                        FileType::RegularFile
                                    };
                                    reply.add(info.node, index + 1, kind, name)
                                }
                                None => { false }
                            }
                        } else { true }
                    });
                    reply.ok();
                }
                None => {
                    reply.error(ENOENT)
                }
            }
        })
    }

    fn readdirplus(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        reply: fuser::ReplyDirectoryPlus,
    ) {
        debug!(
            "[Not Implemented] readdirplus(ino: {:#x?}, fh: {}, offset: {})",
            ino, fh, offset
        );
        reply.error(ENOSYS);
    }

    fn releasedir(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        reply: fuser::ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsyncdir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(
            "[Not Implemented] fsyncdir(ino: {:#x?}, fh: {}, datasync: {})",
            ino, fh, datasync
        );
        reply.error(ENOSYS);
    }

    fn statfs(&mut self, _req: &fuser::Request<'_>, _ino: u64, reply: fuser::ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
    }

    fn setxattr(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        name: &std::ffi::OsStr,
        _value: &[u8],
        flags: i32,
        position: u32,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(
            "[Not Implemented] setxattr(ino: {:#x?}, name: {:?}, flags: {:#x?}, position: {})",
            ino, name, flags, position
        );
        reply.error(ENOSYS);
    }

    fn getxattr(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        name: &std::ffi::OsStr,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        debug!(
            "[Not Implemented] getxattr(ino: {:#x?}, name: {:?}, size: {})",
            ino, name, size
        );
        reply.error(ENOSYS);
    }

    fn listxattr(&mut self, _req: &fuser::Request<'_>, ino: u64, size: u32, reply: fuser::ReplyXattr) {
        debug!(
            "[Not Implemented] listxattr(ino: {:#x?}, size: {})",
            ino, size
        );
        reply.error(ENOSYS);
    }

    fn removexattr(&mut self, _req: &fuser::Request<'_>, ino: u64, name: &std::ffi::OsStr, reply: fuser::ReplyEmpty) {
        debug!(
            "[Not Implemented] removexattr(ino: {:#x?}, name: {:?})",
            ino, name
        );
        reply.error(ENOSYS);
    }

    fn access(&mut self, _req: &fuser::Request<'_>, ino: u64, mask: i32, reply: fuser::ReplyEmpty) {
        debug!("[Not Implemented] access(ino: {:#x?}, mask: {})", ino, mask);
        reply.error(ENOSYS);
    }

    fn create(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        debug!(
            "create(parent: {:#x?}, name: {:?}, mode: {}, umask: {:#x?}, \
            flags: {:#x?})",
            parent, name, mode, umask, flags
        );
        let server = self.server.clone();
        let name_str: String = name.to_string_lossy().into();
        let uid = _req.uid();
        let gid = _req.gid();
        let info_cache = self.info_cache.clone();
        self.run(move || {
            match server.create_file(parent, &name_str) {
                Ok(info) => {
                    let attr = info.to_attr(uid, gid);
                    info_cache.add_info(parent, &name_str, &info);
                    reply.created(&SLOT_TTL, &attr, 1, 0, flags as u32)
                },
                Err(_) => reply.error(ENOSYS),
            }
        })
    }

    fn getlk(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        reply: fuser::ReplyLock,
    ) {
        debug!(
            "[Not Implemented] getlk(ino: {:#x?}, fh: {}, lock_owner: {}, start: {}, \
            end: {}, typ: {}, pid: {})",
            ino, fh, lock_owner, start, end, typ, pid
        );
        reply.error(ENOSYS);
    }

    fn setlk(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        lock_owner: u64,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        sleep: bool,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(
            "[Not Implemented] setlk(ino: {:#x?}, fh: {}, lock_owner: {}, start: {}, \
            end: {}, typ: {}, pid: {}, sleep: {})",
            ino, fh, lock_owner, start, end, typ, pid, sleep
        );
        reply.error(ENOSYS);
    }

    fn bmap(&mut self, _req: &fuser::Request<'_>, ino: u64, blocksize: u32, idx: u64, reply: fuser::ReplyBmap) {
        debug!(
            "[Not Implemented] bmap(ino: {:#x?}, blocksize: {}, idx: {})",
            ino, blocksize, idx,
        );
        reply.error(ENOSYS);
    }

    fn ioctl(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        flags: u32,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
        reply: fuser::ReplyIoctl,
    ) {
        debug!(
            "[Not Implemented] ioctl(ino: {:#x?}, fh: {}, flags: {}, cmd: {}, \
            in_data.len(): {}, out_size: {})",
            ino,
            fh,
            flags,
            cmd,
            in_data.len(),
            out_size,
        );
        reply.error(ENOSYS);
    }

    fn fallocate(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
        reply: fuser::ReplyEmpty,
    ) {
        debug!(
            "[Not Implemented] fallocate(ino: {:#x?}, fh: {}, offset: {}, \
            length: {}, mode: {})",
            ino, fh, offset, length, mode
        );
        reply.error(ENOSYS);
    }

    fn lseek(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        whence: i32,
        reply: fuser::ReplyLseek,
    ) {
        debug!(
            "[Not Implemented] lseek(ino: {:#x?}, fh: {}, offset: {}, whence: {})",
            ino, fh, offset, whence
        );
        reply.error(ENOSYS);
    }

    fn copy_file_range(
        &mut self,
        _req: &fuser::Request<'_>,
        ino_in: u64,
        fh_in: u64,
        offset_in: i64,
        ino_out: u64,
        fh_out: u64,
        offset_out: i64,
        len: u64,
        flags: u32,
        reply: fuser::ReplyWrite,
    ) {
        debug!(
            "[Not Implemented] copy_file_range(ino_in: {:#x?}, fh_in: {}, \
            offset_in: {}, ino_out: {:#x?}, fh_out: {}, offset_out: {}, \
            len: {}, flags: {})",
            ino_in, fh_in, offset_in, ino_out, fh_out, offset_out, len, flags
        );
        reply.error(ENOSYS);
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Serialize, Deserialize)]
enum ContentKind {
    File,
    Directory,
    SymbolicLink,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ContentInformation {
    node: u64,
    kind: ContentKind,

    #[serde(rename = "modifyTime")]
    modify_time: u64,

    #[serde(rename = "createTime")]
    create_time: u64,
    executable: bool,
    writable: bool,
    etag: String,
    size: Option<u64>,
    target: Option<String>,

    #[serde(rename = "type")]
    content_type: Option<String>,
}

impl ContentInformation {
    fn to_attr(&self, uid: u32, gid: u32) -> FileAttr {
        let mtime = UNIX_EPOCH + Duration::from_millis(self.modify_time);
        let ctime = UNIX_EPOCH + Duration::from_millis(self.create_time);
        let kind = if self.kind == ContentKind::File { FileType::RegularFile } else { FileType::Directory };
        let w = if self.writable { 0o200u16 } else { 0o000u16 };
        let x  = if self.executable { 0o100u16 } else { 0o000u16 };
        let base = if kind == FileType::RegularFile { 0o444 } else { 0o455 };
        let perm = base | x | w;
        FileAttr {
            ino: self.node,
            size: self.size.unwrap_or(0),
            blocks: 1,
            ctime,
            mtime,
            atime: mtime,
            crtime: ctime,
            kind,
            perm,
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            blksize: 1,
            flags: 0
        }
    }
}

#[derive(Serialize, Deserialize)]
struct EntryAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    executable: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    writable: Option<bool>,

    #[serde(rename = "modifyTime", skip_serializing_if = "Option::is_none")]
    modify_time: Option<u64>,

    #[serde(rename = "createTime", skip_serializing_if = "Option::is_none")]
    create_time: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,

    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
}

impl EntryAttributes {
    fn new(
        mode: Option<u32>,
        mtime: Option<fuser::TimeOrNow>,
        ctime: Option<std::time::SystemTime>,
        size: Option<u64>
    ) -> Result<Self> {
        let executable = mode.and_then(|mode| Some((mode & X_BIT) != 0));
        let writable = mode.and_then(|mode| Some((mode & W_BIT) != 0));
        debug!("EntryAttributes: executable={:?} writable={:?}", executable, writable);
        let modify_time_duration = invert(mtime.and_then(|mtime| match mtime {
            fuser::TimeOrNow::SpecificTime(system_time) => Some(system_time),
            fuser::TimeOrNow::Now => Some(SystemTime::now()),
        }).and_then(|mtime| Some(mtime.duration_since(UNIX_EPOCH))))?;
        let modify_time = modify_time_duration.and_then(|mtime| Some(mtime.as_millis() as u64));
        let create_time_duration =
            invert(ctime.and_then(|ctime| Some(ctime.duration_since(UNIX_EPOCH))))?;
        let create_time = create_time_duration.and_then(|ctime| Some(ctime.as_millis() as u64));
        Ok(
            Self {
                executable,
                writable,
                modify_time,
                create_time,
                size,
                content_type: None
            }
        )
    }
}

#[derive(Serialize, Deserialize)]
struct FileDirectoryEntry {
    name: String,
    info: ContentInformation,
}

fn invert<T, E>(x: Option<std::result::Result<T, E>>) -> std::result::Result<Option<T>, E> {
    x.map_or(Ok(None), |v | v.map(Some))
}

const X_BIT: u32 = 0o100;
const W_BIT: u32 = 0o200;

const SLOT_TTL: std::time::Duration = std::time::Duration::from_secs(30);
