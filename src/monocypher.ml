(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

module Rand = struct
  external getrandom : Bigstring.t -> int -> int =
    "caml_monocypher_getrandom" [@@noalloc]

  let gen buflen =
    let buf = Bigstring.create buflen in
    let nb_written = getrandom buf buflen in
    if nb_written <> buflen then
      invalid_arg "Rand.gen: RNG failed" ;
    buf

  let write ?len buf =
    let buflen = Bigstring.length buf in
    let len = match len with
      | None -> buflen
      | Some l when l < 0 ->
        invalid_arg (Printf.sprintf "Rand.write: len=%d is negative" l)
      | Some l when l > buflen ->
        invalid_arg (Printf.sprintf "Rand.write: len=%d > buflen=%d " l buflen)
      | Some l -> l in
    getrandom buf len
end
(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
  ---------------------------------------------------------------------------*)
