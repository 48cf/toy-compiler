fn strlen(str) [len] {
  = len 0
  while != ($read8 str) 0 {
    = len (+ len 1)
    = str (+ str 1)
  }
  ret len
}

fn memcpy(from, to, len) void {
  while > len 0 {
    $write8 to ($read8 from)
    = from (+ from 1)
    = to (+ to 1)
    = len (- len 1)
  }
  ret
}

fn memset(buf, value, len) void {
  while > len 0 {
    $write8 buf value
    = buf (+ buf 1)
    = len (- len 1)
  }
}

fn digit_char(value) {
  if >= value 10 {
    ret + (- value 10) 'A'
  } else {
    ret + '0' value
  }
}
