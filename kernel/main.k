import "limine.k" limine
import "print.k" print

fn _start() [idx, entry] void {
  print.format "Hello %s!\n" ["world"]

  = idx 0
  while < idx (limine.mmap_resp_entry_count limine.mmap_req_resp) {
    = entry (limine.mmap_resp_entry limine.mmap_req_resp idx)
    = idx (+ idx 1)

    print.format "  %x .. %x : %s\n" [
      (limine.mmap_entry_base entry)
      (+ (limine.mmap_entry_base entry) (limine.mmap_entry_length entry))
      (limine.mmap_entry_type_str (limine.mmap_entry_type entry))
    ]
  }

  $writecr 3 ($readcr 3)

  while 1 {
    $halt
  }

  $unreachable
}
