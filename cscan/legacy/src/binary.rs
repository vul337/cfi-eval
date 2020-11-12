use capstone::prelude::*;
use dfuzz_os::process::Process;
use goblin::elf;
use log::*;
use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug)]
pub struct Elf {
    pub buf: Vec<u8>,
    pub elf: goblin::elf::Elf<'static>,
    pub disasm: Capstone,

    pub addr_load: u64, // address where the binary is actually load
    pub addr_base: u64, // address where the binary expects to be load
}

impl Elf {
    pub fn symbol_by_filter<F: Fn(&str) -> bool>(&self, filter: F) -> Option<elf::Sym> {
        self.elf.syms.iter().find(|sym| {
            if let Some(Ok(sym_name)) = self.elf.strtab.get(sym.st_name) {
                if filter(sym_name) {
                    return true;
                }
            }
            false
        })
    }

    pub fn symbol_by_name(&self, name: &str) -> elf::Sym {
        self.symbol_by_filter(|sym_name| sym_name == name)
            .unwrap_or_else(|| panic!("cannot find symbol named `{}`", name))
    }

    /// Converts an address to the symbol.
    pub fn symbol_by_vma(&self, vma: u64) -> elf::Sym {
        self.elf
            .syms
            .iter()
            .find(|sym| sym.st_value <= vma && sym.st_value + sym.st_size > vma)
            .unwrap_or_else(|| panic!("cannot find symbol covering vma {:#x}", vma))
    }

    pub fn symbol_to_load(&self, name: &str) -> (u64, usize) {
        let sym = self.symbol_by_name(name);
        let start = self.vma_to_load(sym.st_value);
        (start, sym.st_size as _)
    }

    pub fn offset_to_vma(&self, offset: u64) -> u64 {
        self.addr_base + offset
    }

    pub fn vma_to_offset(&self, vma: u64) -> u64 {
        vma - self.addr_base
    }

    pub fn load_to_vma(&self, load: u64) -> u64 {
        load - self.addr_load + self.addr_base
    }

    pub fn vma_to_load(&self, vma: u64) -> u64 {
        vma - self.addr_base + self.addr_load
    }

    /// Loads the binary from process, with calculated offset.
    /// filename is None: opens the binary itself
    pub fn from_process(process: Process, filename: Option<&OsStr>) -> Elf {
        let procfs = process.to_procfs().unwrap();
        let filename: Cow<'_, OsStr> = filename
            .map(|filename| filename.into())
            .unwrap_or_else(|| OsString::from(procfs.exe().unwrap()).into());

        let vmmap = procfs.maps().unwrap();
        let (filename, addr_load) = vmmap
            .iter()
            .find_map(|segment| {
                if let procfs::MMapPath::Path(path) = &segment.pathname {
                    if path.as_os_str() == filename || path.file_name() == Some(filename.as_ref()) {
                        return Some((path, segment.address.0));
                    }
                }
                None
            })
            .expect("cannot find address in vmmap");

        let mut this = Self::from_path(filename);
        debug!("elf load = {:#x}", addr_load);
        this.addr_load = addr_load;
        this
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Elf {
        use goblin::Object;
        let mut file = File::open(path.as_ref()).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        let mut r = std::mem::MaybeUninit::<Elf>::uninit();
        let (buf_ptr, elf_ptr, disasm_ptr) = unsafe {
            (
                &mut (*r.as_mut_ptr()).buf as *mut Vec<u8>,
                &mut (*r.as_mut_ptr()).elf as *mut elf::Elf,
                &mut (*r.as_mut_ptr()).disasm as *mut Capstone,
            )
        };

        unsafe {
            buf_ptr.write(buf);
        }
        let obj = Object::parse(unsafe { &*buf_ptr }).unwrap();
        let elf = match obj {
            Object::Elf(elf) => elf,
            _ => panic!("failed to parse elf"),
        };
        use elf::program_header::*;
        let addr_base = elf
            .program_headers
            .iter()
            .find(|hdr| hdr.p_type == PT_LOAD && hdr.p_offset == 0)
            .expect("cannot locate elf base")
            .p_vaddr;

        use capstone::arch::x86::{ArchMode, ArchSyntax};
        let disasm = capstone::Capstone::new()
            .x86()
            .mode(if elf.is_64 {
                ArchMode::Mode64
            } else {
                ArchMode::Mode32
            })
            .syntax(ArchSyntax::Intel)
            .detail(true)
            .build()
            .expect("cannot setup disassembler");

        debug!(
            "elf path = {:?}, is_64 = {}, base = {:#x}",
            path.as_ref(),
            elf.is_64,
            addr_base
        );
        unsafe {
            elf_ptr.write(elf);
            disasm_ptr.write(disasm);
            (*r.as_mut_ptr()).addr_base = addr_base;
            (*r.as_mut_ptr()).addr_load = addr_base; // assume so
            r.assume_init()
        }
    }
}
