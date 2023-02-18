import "io.k" io
import "sys.k" sys

fn main(argc, argv, envp) [index] {
  = index 0
  io.print_fmt "Got %d arguments:\n" [argc]
  while < index argc {
    io.print_fmt " - %s'\n" [$read64 (+ argv * index 8)]
    = index (+ index 1)
  }
  ret 0
}

fn _start() [code] {
  = code $entry main
  io.flush
  sys.exit code
}
