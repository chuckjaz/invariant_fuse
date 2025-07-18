use bytes::Bytes;
use fuser::{FileAttr, FileType, Filesystem};
use reqwest::{blocking::{Body, Client}, Url};
use libc::{c_int, ENOENT, ENOSYS, EPERM};
use log::debug;
use serde::{Deserialize, Serialize};
use std::{time::{Duration, SystemTime, UNIX_EPOCH}};
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
    fn lookup(&self, parent: u64, name: &str) -> Result<u64> {
        let path = format!("files/lookup/{parent}/{name}");
        let url = self.url.join(&path)?;
        let text = Client::new().get(url).send()?.text()?;
        let node = text.parse::<u64>()?;

        Ok(self.node_out(node))
    }

    fn info(&self, node: u64) -> Result<ContentInformation> {
        let in_node = self.node_in(node);
        let path = format!("files/info/{in_node}");
        let url = self.url.join(&path)?;
        debug!("FileFuse::info url={url}");
        let text = Client::new().get(url).send()?.text()?;
        let content_info = serde_json::from_str::<ContentInformation>(&text)?;

        Ok(content_info)
    }

    fn lookup_info(&self, parent: u64, name: &str) -> Result<ContentInformation> {
        let in_parent = self.node_in(parent);
        let node = self.lookup(in_parent, name)?;
        let info = self.info(node)?;

        Ok(info)
    }

    fn setattr(&self, node: u64, attr: &EntryAttributes) -> Result<()> {
        let in_node = self.node_in(node);
        let path = format!("files/attributes/{in_node}");
        let url = self.url.join(&path)?;
        let attr_text = serde_json::to_string(attr)?;
        Client::new().put(url).body(attr_text).send()?;

        Ok(())
    }

    fn setattr_info(&self, node: u64, attr: &EntryAttributes) -> Result<ContentInformation> {
        let in_node = self.node_in(node);
        self.setattr(in_node, attr)?;

        self.info(node)
    }

    fn setattr_info_spec(
        &self,
        node: u64,
        mode: Option<u32>,
        mtime: Option<fuser::TimeOrNow>,
        ctime: Option<std::time::SystemTime>
    ) -> Result<ContentInformation> {
        let in_node = self.node_in(node);
        let attr = EntryAttributes::new(mode, mtime, ctime)?;
        self.setattr_info(in_node, &attr)
    }

    fn make_node(&self, parent: u64, name: &str, kind: ContentKind) -> Result<u64> {
        let in_parent = self.node_in(parent);
        let path = format!("files/{in_parent}/{name}");
        let mut url = self.url.join(&path)?;
        if kind == ContentKind::Directory {
            url.set_query(Some("kind=Directory"))
        }
        let node_text = Client::new().put(url).send()?.text()?;
        let node = node_text.parse::<u64>()?;
        let node_out = self.node_out(node);

        Ok(node_out)
    }

    fn make_node_info(&self, parent: u64, name: &str, kind: ContentKind) -> Result<ContentInformation> {
        let in_parent = self.node_in(parent);
        let node = self.make_node(in_parent, name, kind)?;
        let node_out = self.node_out(node);

        self.info(node_out)
    }

    fn remove_node(&self, parent: u64, name: &str) -> Result<bool> {
        let in_parent = self.node_in(parent);
        let path = format!("files/remove/{in_parent}/{name}");
        let url = self.url.join(&path)?;
        let text = Client::new().post(url).send()?.text()?;

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
        let response = Client::new().post(url).send()?;

        Ok(response.status() == 200)
    }

    fn link_node(&self, parent: u64, node: u64, name: &str) -> Result<bool> {
        let in_parent = self.node_in(parent);
        let in_node = self.node_in(node);
        let path = format!("files/link/{in_parent}/{name}");
        let mut url = self.url.join(&path)?;
        let node = format!("node={in_node}");
        url.set_query(Some(&node));
        let response = Client::new().post(url).send()?;

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
        let response = Client::new().get(url).send()?;
        Ok(response.bytes()?)
    }

    fn write_node(&self, node: u64, offset: u64, data: &[u8]) -> Result<u64> {
        let in_node = self.node_in(node);
        let path = format!("files/{in_node}");
        let mut url = self.url.join(&path)?;
        let offset_option = format!("offset={offset}");
        url.set_query(Some(&offset_option));
        let bytes = Bytes::copy_from_slice(data);
        let body = Body::from(bytes);
        let response = Client::new().post(url).body(body).send()?;
        let text = response.text()?;
        let written: u64 = text.parse()?;
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
        let text = Client::new().get(url).send()?.text()?;
        Ok(serde_json::from_str(&text)?)
    }

    fn sync(&self) -> Result<()> {
        let url = self.url.join("/files/sync")?;
        Client::new().put(url).send()?;
        Ok(())
    }

    fn node_out(&self, node: u64) -> u64 {
        if node == self.root {
            1
        } else {
            node
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

/// A file system implementation that uses the Files Server API
pub struct FilesFuse {
    /// The file server
    server: FilesServer,

    /// Thread pool to use
    thread_pool: ThreadPool,
}

impl FilesFuse {
    pub fn create(url: Url, root: u64) -> Self {
        Self { server: FilesServer { url, root }, thread_pool: ThreadPool::new(8) }
    }

    pub fn mount(url: Url, content_link: String) -> Result<Self> {
        let path = format!("files/mount");
        let mount_url = url.clone().join(&path)?;
        let body = Body::from(content_link);
        let text = Client::new().post(mount_url.clone()).body(body).send()?.text()?;
        debug!("mount response: {text}");
        let root = text.parse::<u64>()?;
        Ok(Self { server: FilesServer { url, root }, thread_pool: ThreadPool::new(8) })
    }


    fn run<F: FnOnce() + Send + 'static>(&mut self, f: F) {
        self.thread_pool.execute(f);
    }
}

impl Filesystem for FilesFuse {
    fn init(&mut self, _req: &fuser::Request<'_>, _config: &mut fuser::KernelConfig) -> std::result::Result<(), c_int> {
        Ok(())
    }

    fn destroy(&mut self) {}

    fn lookup(&mut self, _req: &fuser::Request<'_>, parent: u64, name: &std::ffi::OsStr, reply: fuser::ReplyEntry) {
        debug!("lookup(parent: {:#x?}, name {:?})", parent, name);
        let server = self.server.clone();
        let uid = _req.uid();
        let gid = _req.gid();
        let name_str: String = name.to_string_lossy().into();
        self.run(move || {
            match server.lookup_info(parent, &name_str) {
                Ok(info) => {
                    let attr = info.to_attr(uid, gid);
                    reply.entry(&SLOT_TTL, &attr, 1)
                },
                Err(_) => reply.error(ENOENT),
            }
        });
    }

    fn forget(&mut self, _req: &fuser::Request<'_>, _ino: u64, _nlookup: u64) {}

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, fh: Option<u64>, reply: fuser::ReplyAttr) {
        debug!("getattr(ino: {:#x?}, fh: {:#x?})", ino, fh);
        let server = self.server.clone();
        let uid = _req.uid();
        let gid = _req.gid();
        self.run(move || {
            match server.info(ino) {
                Ok(info) => {
                    let attr = info.to_attr(uid, gid);
                    reply.attr(&SLOT_TTL, &attr)
                },
                Err(err) => {
                    debug!("getattr({ino:#x?}: err: {err}");
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
        debug!("setattr(ino: {:#x?}, mode: {:?}, uid: {:?}, gid: {:?}, size: {:?}, fh: {:?}, flags: {:?})",
            ino, mode, uid, gid, size, fh, flags
        );
        let server = self.server.clone();
        let effective_uid = _req.uid();
        let effective_gid = _req.gid();
        self.run(move || {
            match server.setattr_info_spec(ino, mode, _mtime, _ctime) {
                Ok(info) => {
                    let attr = info.to_attr(effective_uid, effective_gid);
                    reply.attr(&SLOT_TTL, &attr)
                },
                Err(_) => reply.error(ENOENT)
            }
        })
    }

    fn readlink(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyData) {
        debug!("[Not Implemented] readlink(ino: {:#x?})", ino);
        reply.error(ENOSYS);
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
        debug!("mknod(parent: {:#x?}, name: {:?}, mode: {}, umask: {:#x?}, rdev: {})",
            parent, name, mode, umask, rdev
        );
        let server = self.server.clone();
        let uid = _req.uid();
        let gid = _req.gid();
        let name_str: String = name.to_string_lossy().into();
        self.run(move || {
            match server.make_node_info(parent, &name_str, ContentKind::File) {
                Ok(info) => {
                    let attr = info.to_attr(uid, gid);
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
        debug!("mkdir(parent: {:#x?}, name: {:?}, mode: {}, umask: {:#x?})",
            parent, name, mode, umask
        );
        let server = self.server.clone();
        let name_str: String = name.to_string_lossy().into();
        let uid = _req.uid();
        let gid = _req.gid();
        self.run(move || {
            match server.make_node_info(parent, &name_str, ContentKind::Directory) {
                Ok(info) => {
                    let attr = info.to_attr(uid, gid);
                    reply.entry(&SLOT_TTL, &attr, 1)
                },
                Err(_) => reply.error(ENOSYS),
            }

        })
    }

    fn unlink(&mut self, _req: &fuser::Request<'_>, parent: u64, name: &std::ffi::OsStr, reply: fuser::ReplyEmpty) {
        debug!("unlink(parent: {:#x?}, name: {:?})", parent, name);
        let server = self.server.clone();
        let name_str: String = name.to_string_lossy().into();
        self.run(move || {
            match server.remove_node(parent, &name_str) {
                Ok(result) => if result { reply.ok() } else { reply.error(ENOENT) }
                Err(_) => reply.error(ENOSYS),
            }
        })
    }

    fn rmdir(&mut self, _req: &fuser::Request<'_>, parent: u64, name: &std::ffi::OsStr, reply: fuser::ReplyEmpty) {
        debug!("rmdir(parent: {:#x?}, name: {:?})", parent, name);
        let server = self.server.clone();
        let name_str: String = name.to_string_lossy().into();
        self.run(move || {
            match server.remove_node(parent, &name_str) {
                Ok(result) => if result { reply.ok() } else { reply.error(ENOENT) }
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
        debug!(
            "[Not Implemented] symlink(parent: {:#x?}, link_name: {:?}, target: {:?})",
            parent, link_name, target,
        );
        reply.error(EPERM);
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
        debug!("rename(parent: {:#x?}, name: {:?}, newparent: {:#x?},  newname: {:?}, flags: {})",
            parent, name, newparent, newname, flags,
        );
        let server = self.server.clone();
        let name_str: String = name.to_string_lossy().into();
        let new_name_str: String = newname.to_string_lossy().into();
        self.run(move || {
            match server.rename_node(parent, &name_str, newparent, &new_name_str) {
                Ok(result) => if result { reply.ok() } else { reply.error(ENOENT) }
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
        debug!("link(ino: {:#x?}, newparent: {:#x?}, newname: {:?})",
            ino, newparent, newname
        );
        let server = self.server.clone();
        let new_name_str: String = newname.to_string_lossy().into();
        let uid = _req.uid();
        let gid = _req.gid();
        self.run(move || {
            match server.link_info(newparent, ino, &new_name_str) {
                Ok(result) => match result {
                    Some(info) => {
                        let attr = info.to_attr(uid, gid);
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
        debug!("read(ino: {:#x?}, fh: {}, offset: {}, size: {}, flags: {:#x?}, lock_owner: {:?})",
            ino, fh, offset, size, flags, lock_owner
        );
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
        debug!("write(ino: {:#x?}, fh: {}, offset: {}, data.len(): {}, write_flags: {:#x?}, flags: {:#x?}, lock_owner: {:?})",
            ino,
            fh,
            offset,
            data.len(),
            write_flags,
            flags,
            lock_owner
        );
        let server = self.server.clone();
        let effective_offset: u64 = offset.try_into().unwrap();
        let data_buf = Vec::from(data);
        self.run(move || {
            match server.write_node(ino, effective_offset, &data_buf) {
                Ok(written) => reply.written(written.try_into().unwrap()),
                Err(_) => reply.error(ENOSYS),
            }
        })
    }

    fn flush(&mut self, _req: &fuser::Request<'_>, ino: u64, fh: u64, lock_owner: u64, reply: fuser::ReplyEmpty) {
        debug!("flush(ino: {:#x?}, fh: {}, lock_owner: {:?})", ino, fh, lock_owner );
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
        debug!("fsync(ino: {:#x?}, fh: {}, datasync: {})",
            ino, fh, datasync
        );
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
        debug!("readdir(ino: {:#x?}, fh: {}, offset: {})",
            ino, fh, offset
        );
        let server = self.server.clone();
        let effective_offset = offset.try_into().unwrap();
        self.run(move || {
            match server.read_directory(ino, effective_offset) {
                Ok(entries) => {
                    let mut off = offset;
                    debug!("readdir: entries.len {}", entries.len());
                    for entry in entries {
                        let kind = if entry.kind == ContentKind::Directory {
                            FileType::Directory
                        } else {
                            FileType::RegularFile
                        };
                        if reply.add(entry.node, off + 1, kind, &entry.name) {
                            break;
                        }
                        off += 1;
                    }
                    reply.ok();
                },
                Err(err) => {
                    debug!("readdir: err {err}");
                    reply.error(ENOSYS)
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
        self.run(move || {
            match server.make_node_info(parent, &name_str, ContentKind::File) {
                Ok(info) => {
                    let attr = info.to_attr(uid, gid);
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
}

#[derive(Serialize, Deserialize, Debug)]
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

    #[serde(rename = "contentType")]
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

    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
}

impl EntryAttributes {
    fn new(
        mode: Option<u32>,
        mtime: Option<fuser::TimeOrNow>,
        ctime: Option<std::time::SystemTime>,
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
                content_type: None
            }
        )
    }
}

#[derive(Serialize, Deserialize)]
struct FileDirectoryEntry {
    name: String,
    kind: ContentKind,
    node: u64
}

fn invert<T, E>(x: Option<std::result::Result<T, E>>) -> std::result::Result<Option<T>, E> {
    x.map_or(Ok(None), |v | v.map(Some))
}

const X_BIT: u32 = 0o100;
const W_BIT: u32 = 0o200;

const SLOT_TTL: std::time::Duration = std::time::Duration::from_secs(30);
