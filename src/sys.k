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
