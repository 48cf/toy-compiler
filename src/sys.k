const PROT_NONE 0x0
const PROT_READ 0x1
const PROT_WRITE 0x2
const PROT_EXEC 0x4
const PROT_GROWSDOWN 0x1000000
const PROT_GROWSUP 0x2000000

const MAP_SHARED 0x1
const MAP_PRIVATE 0x2
const MAP_SHARED_VALIDATE 0x3
const MAP_FIXED 0x10
const MAP_ANONYMOUS 0x20

fn exit(code) void {
  $syscall [60 code]
  $unreachable
}

fn write(fd, buf, len) {
  ret $syscall [1 fd buf len]
}

fn write_all(fd, buf, len) [written] void {
  while > len 0 {
    = written write fd buf len
    = buf + buf written
    = len - len written
  }
  ret
}

fn mmap(hint, length, prot, flags, fd, offset) {
  ret $syscall [9 hint length prot flags fd offset]
}
