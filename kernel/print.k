import "lib.k" lib
import "limine.k" limine

var terminal
var term_write

var int_buffer[128]
var buffer[0x1000]
var written

fn __flush_internal() void {
  if == terminal 0 {
    = term_write (limine.term_resp_term_write limine.term_req_resp)
    = terminal (limine.term_resp_terminal limine.term_req_resp 0)
  }
  $ccall term_write [terminal buffer written]
  = written 0
  ret
}

fn __char_unchecked(ch) void {
  $write8 (+ buffer written) ch
  = written (+ written 1)
  if == ch '\n' {
    __flush_internal
  }
  ret
}

fn flush() void {
  if > written 0 {
    __flush_internal
  }
  ret
}

fn char(ch) void {
  if > (+ written 1) ($sizeof buffer) {
    __flush_internal
  }
  __char_unchecked ch
  ret
}

fn str(value) [len] void {
  = len (lib.strlen value)
  if > (+ written len) ($sizeof buffer) {
    __flush_internal
  }
  while > len 0 {
    __char_unchecked ($read8 value)
    = len (- len 1)
    = value (+ value 1)
  }
  ret
}

fn int(val, base) [offset, ch] void {
  if == val 0 {
    $write8 (+ int_buffer 0) '0'
    = offset 1
  } else {
    = offset 0
    while > val 0 {
      $write8 (+ int_buffer offset) (lib.digit_char % val base)
      = val (/ val base)
      = offset (+ offset 1)
    }
  }
  if == base 2 {
    str "0b"
  } else if == base 8 {
    str "0o"
  } else if == base 16 {
    str "0x"
  }
  while > offset 0 {
    = offset (- offset 1)
    char $read8 (+ int_buffer offset)
  }
  ret
}

fn format(fmt, ...) [arg, index, spec] void {
  = index 0
  while != ($read8 fmt) 0 {
    if == ($read8 fmt) '%' {
      if == index $argc {
        str "There was not enough arguments for specified format string\n"
        flush
        $unreachable
      }
      = arg ($arg index)
      = index (+ index 1)
      = spec ($read8 + fmt 1)
      = fmt (+ fmt 2)
      // TODO: Implement switches
      if == spec '%' {
        char '%'
      } else if == spec 's' {
        str arg
      } else if == spec 'b' {
        int arg 2
      } else if == spec 'o' {
        int arg 8
      } else if == spec 'd' {
        int arg 10
      } else if == spec 'x' {
        int arg 16
      } else {
        char '%'
        char spec
      }
    } else {
      char ($read8 fmt)
      = fmt (+ fmt 1)
    }
  }
  ret
}

fn assert(expr, fmt, ...) void {
  if == expr 0 {
    format fmt [$fwargs]
    flush
    $unreachable
  }
  ret
}
