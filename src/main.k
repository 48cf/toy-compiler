import "io.k" io
import "sys.k" sys
import "mem.k" mem

var emit_text_buffer
var emit_data_buffer

fn main(argc, argv, envp) {
  if < argc 3 {
    io.print_fmt "Usage: %s <input file> <output file>\n" [$read64 argv]
    ret 1
  }

  = emit_text_buffer (
    sys.mmap 0 0x80000
    | sys.PROT_READ sys.PROT_WRITE
    | sys.MAP_ANONYMOUS sys.MAP_PRIVATE
    -1 0
  )
  io.assert > emit_text_buffer 0 "Failed to map code buffer\n" []

  = emit_data_buffer (
    sys.mmap 1231231983 0x800001231231
    | sys.PROT_READ sys.PROT_WRITE
    | sys.MAP_ANONYMOUS sys.MAP_PRIVATE
    -1 0
  )
  io.assert > emit_data_buffer 0 "Failed to map data buffer\n" []

  ret 0
}

fn _start() [code] {
  = code $entry main
  io.flush
  sys.exit code
}
