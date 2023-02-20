const LIMINE_MAGIC1 0xc7b1dd30df4c8b88
const LIMINE_MAGIC2 0x0a82e883a194f07b

// Stack size request
var stack_size_req_id0 LIMINE_MAGIC1
var stack_size_req_id1 LIMINE_MAGIC2
var stack_size_req_id2 0x224ef0460a8e8926
var stack_size_req_id3 0xe1cb0fc25f46ea3d

var stack_size_req_rev 0
var stack_size_req_resp 0
var stack_size_size 0x10000

// Stack size response
fn stack_size_resp_rev(resp) {
  ret $read64 resp
}

// Higher-half direct map request
var hhdm_req_id0 LIMINE_MAGIC1
var hhdm_req_id1 LIMINE_MAGIC2
var hhdm_req_id2 0x48dcf1cb8ad2b852
var hhdm_req_id3 0x63984e959a98244b

var hhdm_req_rev 0
var hhdm_req_resp 0

// Higher-half direct map response
fn hhdm_resp_rev(resp) {
  ret $read64 resp
}

fn hhdm_resp_offset(resp) {
  ret $read64 (+ resp 8)
}

// TODO: Framebuffer request

// Terminal request
var term_req_id0 LIMINE_MAGIC1
var term_req_id1 LIMINE_MAGIC2
var term_req_id2 0xc8ac59310c2b0844
var term_req_id3 0xa68d0c7265d38878

var term_req_rev 0
var term_req_resp 0
var term_req_callback 0

fn term_resp_rev(resp) {
  ret $read64 resp
}

fn term_resp_term_count(resp) {
  ret $read64 (+ resp 8)
}

fn term_resp_terminal(resp, index) {
  ret $read64 (+ $read64 (+ resp 16) (* index 8))
}

fn term_resp_term_write(resp) {
  ret $read64 (+ resp 24)
}

// TODO: 5-level paging request
// TODO: SMP request

// Memory map request

const MMAP_USABLE 0
const MMAP_RESERVED 1
const MMAP_ACPI_RECLAIMABLE 2
const MMAP_ASCI_NVS 3
const MMAP_BAD_MEMORY 4
const MMAP_BOOTLOADER_RECLAIMABLE 5
const MMAP_KERNEL 6
const MMAP_FRAMEBUFFER 7

var mmap_req_id0 LIMINE_MAGIC1
var mmap_req_id1 LIMINE_MAGIC2
var mmap_req_id2 0x67cf3d9d378a806f
var mmap_req_id3 0xe304acdfc50c3c62

var mmap_req_rev 0
var mmap_req_resp 0

fn mmap_resp_rev(resp) {
  ret $read64 resp
}

fn mmap_resp_entry_count(resp) {
  ret $read64 (+ resp 8)
}

fn mmap_resp_entry(resp, index) {
  ret $read64 (+ $read64 (+ resp 16) (* index 8))
}

fn mmap_entry_base(entry) {
  ret $read64 entry
}

fn mmap_entry_length(entry) {
  ret $read64 (+ entry 8)
}

fn mmap_entry_type(entry) {
  ret $read64 (+ entry 16)
}

fn mmap_entry_type_str(type) {
  if == type MMAP_USABLE {
    ret "MMAP_USABLE"
  } else if == type MMAP_RESERVED {
    ret "MMAP_RESERVED"
  } else if == type MMAP_ACPI_RECLAIMABLE {
    ret "MMAP_ACPI_RECLAIMABLE"
  } else if == type MMAP_ASCI_NVS {
    ret "MMAP_ASCI_NVS"
  } else if == type MMAP_BAD_MEMORY {
    ret "MMAP_BAD_MEMORY"
  } else if == type MMAP_BOOTLOADER_RECLAIMABLE {
    ret "MMAP_BOOTLOADER_RECLAIMABLE"
  } else if == type MMAP_KERNEL {
    ret "MMAP_KERNEL"
  } else if == type MMAP_FRAMEBUFFER {
    ret "MMAP_FRAMEBUFFER"
  } else {
    ret "UNKNOWN"
  }
}

// TODO: Entry point request
// TODO: Kernel file request
// TODO: Modules reuqest
// TODO: RSDP request
// TODO: SMBIOS request
// TODO: EFI system table request
// TODO: Boot time request

// Kernel address request

var kernel_addr_req_id0 LIMINE_MAGIC1
var kernel_addr_req_id1 LIMINE_MAGIC2
var kernel_addr_req_id2 0x71ba76863cc55f63
var kernel_addr_req_id3 0xb2644a48c516a487

var kernel_addr_req_rev 0
var kernel_addr_req_resp 0

fn kernel_addr_resp_rev(resp) {
  ret $read64 resp
}

fn kernel_addr_resp_physical_base(resp) {
  ret $read64 (+ resp 8)
}

fn kernel_addr_resp_virtual_base(resp) {
  ret $read64 (+ resp 16)
}

// TODO: Device tree blob request
