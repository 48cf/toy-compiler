import "lib.k" lib
import "sys.k" sys

var int_buffer[128]
var buffer[0x1000]
var written

fn __flush_internal() void {
  sys.write_all 1 buffer written
  = written 0
  ret
}

fn __print_char_unchecked(ch) void {
  $write8 (+ buffer written) ch
  = written (+ written 1)
  ret
}

fn flush() void {
  if > written 0 {
    __flush_internal
  }
  ret
}

fn print_char(ch) void {
  if > (+ written 1) ($sizeof buffer) {
    __flush_internal
  }
  __print_char_unchecked ch
  ret
}

fn print_str(str) [len] void {
  = len (lib.strlen str)
  if > (+ written len) ($sizeof buffer) {
    __flush_internal
  }
  while > len 0 {
    __print_char_unchecked ($read8 str)
    = len (- len 1)
    = str (+ str 1)
  }
  ret
}

fn print_int(value, base) [offset, ch] void {
  if == value 0 {
    print_str "0"
    ret
  }
  = offset 0
  while > value 0 {
    $write8 (+ int_buffer offset) (lib.digit_char % value base)
    = value (/ value base)
    = offset (+ offset 1)
  }
  while > offset 0 {
    = offset (- offset 1)
    print_char $read8 (+ int_buffer offset)
  }
  ret
}

fn print_fmt(fmt, ...) [arg, index, spec] void {
  = index 0
  while != ($read8 fmt) 0 {
    if == ($read8 fmt) '%' {
      if == index $argc {
        print_str "There was not enough arguments for specified format string\n"
        flush
        $unreachable
      }
      = arg ($arg index)
      = index (+ index 1)
      = spec ($read8 + fmt 1)
      = fmt (+ fmt 2)
      // TODO: Implement switches
      if == spec '%' {
        print_char '%'
      } else if == spec 's' {
        print_str arg
      } else if == spec 'b' {
        print_int arg 2
      } else if == spec 'o' {
        print_int arg 8
      } else if == spec 'd' {
        print_int arg 10
      } else if == spec 'x' {
        print_int arg 16
      } else {
        print_char '%'
        print_char spec
      }
    } else {
      print_char ($read8 fmt)
      = fmt (+ fmt 1)
    }
  }
  ret
}
