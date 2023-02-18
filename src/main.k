import "io.k" io
import "sys.k" sys

fn test1(a, b) {
  io.print_fmt "test1(a=%d b=%d)\n" [a b]
  ret 0
}

fn test2(...) {
  io.print_fmt "test2(($arg 0)=%d ($arg 1)=%d)\n" [$arg 0 $arg 1]
  ret 0
}

var test1_ptr
var test2_ptr

fn main(argc, argv, envp) [index] {
  = test1_ptr $addrof test1
  = test2_ptr $addrof test2

  io.print_fmt "test1_ptr = %x\n" [test1_ptr]
  io.print_fmt "test2_ptr = %x\n" [test2_ptr]

  io.print_str "Calling test1 normally:\n"
  test1 69 420

  io.print_str "Calling test2 normally:\n"
  test2 [69 420]

  io.print_str "Calling test1 through a function pointer:\n"
  $call test1_ptr [69 420]

  io.print_str "Calling test2 through a function pointer:\n"
  $call test2_ptr [] [69 420]

  io.print_str "All done, thank you and goodbye!\n"
  ret 0
}

fn _start() [code] {
  = code $entry main
  io.flush
  sys.exit code
}
