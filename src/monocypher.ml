(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

external wipe : Bigstring.t -> int -> unit =
  "caml_monocypher_crypto_wipe" [@@noalloc]

let check_len buflen = function
  | None -> buflen
  | Some l when l < 0 ->
    invalid_arg (Printf.sprintf "len=%d is negative" l)
  | Some l when l > buflen ->
    invalid_arg (Printf.sprintf "len=%d > buflen=%d " l buflen)
  | Some l -> l

let wipe ?len buf =
  let buflen = Bigstring.length buf in
  let len = check_len buflen len in
  wipe buf len

external equal16 : Bigstring.t -> Bigstring.t -> int =
  "caml_monocypher_crypto_verify16" [@@noalloc]
external equal32 : Bigstring.t -> Bigstring.t -> int =
  "caml_monocypher_crypto_verify32" [@@noalloc]
external equal64 : Bigstring.t -> Bigstring.t -> int =
  "caml_monocypher_crypto_verify64" [@@noalloc]

let equal len a b =
  let alen = Bigstring.length a in
  let blen = Bigstring.length b in
  if alen <> len || blen <> len then
    invalid_arg (Printf.sprintf "equal: len(a)=%d <> %d || len(b)=%d \
                                 <> %d" alen len blen len) ;
  match len with
  | 16 -> equal16 a b = 0
  | 32 -> equal32 a b = 0
  | 64 -> equal64 a b = 0
  | _ -> invalid_arg "Monocypher: internal error"

let equal16 = equal 16
let equal32 = equal 32
let equal64 = equal 64

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
    let len = check_len buflen len in
    getrandom buf len
end

module Hash = struct
  module Blake2b = struct
    external sizeof_ctx : unit -> int =
      "caml_monocypher_sizeof_crypto_blake2b_ctx" [@@noalloc]

    external hash_size : Bigstring.t -> int =
      "caml_monocypher_crypto_blake2b_ctx_hash_size" [@@noalloc]

    external init : Bigstring.t -> int -> Bigstring.t -> unit =
      "caml_monocypher_crypto_blake2b_general_init" [@@noalloc]

    external update : Bigstring.t -> Bigstring.t -> unit =
      "caml_monocypher_crypto_blake2b_update" [@@noalloc]

    external final : Bigstring.t -> Bigstring.t -> unit =
      "caml_monocypher_crypto_blake2b_final" [@@noalloc]

    type ctx = Bigstring.t

    let ctxlen = sizeof_ctx ()

    let init ?(key=Bigstring.empty) len =
      if len < 1 || len > 64 then
        invalid_arg (Printf.sprintf "Hash.Blake2b.init: invalid hash \
                                     size (%d)" len) ;
      let ctx = Bigstring.create ctxlen in
      init ctx len key ;
      ctx

    let blit_final ctx buf =
      let len = hash_size ctx in
      if Bigstring.length buf < len then
        invalid_arg (Printf.sprintf "Hash.Blake2b.blit_final: buffer \
                                     is less than %d bytes" len) ;
      let len = hash_size ctx in
      final ctx buf ;
      len

    let final ctx =
      let hash = Bigstring.create (hash_size ctx) in
      final ctx hash ;
      hash

  end
  module SHA512 = struct
  end
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
