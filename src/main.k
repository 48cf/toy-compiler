import "io.k" io
import "sys.k" sys

fn main(argc, argv, envp) {
  ret 0
}

fn _start() [code] {
  = code $entry main
  io.flush
  sys.exit code
}
