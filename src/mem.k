import "sys.k" sys

const HEAP_SIZE 0x40000

var heap_ptr
var heap_offset
var last_alloc

fn __resize_heap() void {
  = heap_offset 0
  = last_alloc 0
  = heap_ptr (
    sys.mmap 0 HEAP_SIZE
    | sys.PROT_READ sys.PROT_WRITE
    | sys.MAP_ANONYMOUS sys.MAP_PRIVATE
    -1 0
  )
  ret
}

fn alloc(size) [result] {
  = size & (+ size 15) -15
  if | (>= (+ heap_offset size) HEAP_SIZE) (== heap_ptr 0) {
    __resize_heap
  }
  = result (+ heap_ptr heap_offset)
  = heap_offset (+ heap_offset size)
  = last_alloc result
  ret result
}

fn realloc(ptr, new_size) [result] {
  if == last_alloc ptr {
    = heap_offset (+ heap_offset (- new_size (- heap_ptr ptr)))
    ret ptr
  } else {
    ret (alloc new_size)
  }
}

fn free(ptr) void {
  if == last_alloc ptr {
    = heap_offset (- heap_offset (- heap_ptr ptr))
  }
  ret
}
