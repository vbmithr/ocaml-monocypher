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

module Pwhash = struct
  external argon2i :
    Bigstring.t -> Bigstring.t -> int -> Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_crypto_argon2i" [@@noalloc]

  let argon2i ?(nb_blocks=100_000) ?(nb_iter=3) ~password ~salt buf =
    let buflen = Bigstring.length buf in
    if buflen <> 16 && buflen <> 32 && buflen <> 64 then
      invalid_arg (Printf.sprintf "Pwhash.argon2i: buflen (%d) must be \
                                   either 16, 32, or 64" buflen) ;
    let saltlen = Bigstring.length salt in
    if saltlen < 8 then
      invalid_arg (Printf.sprintf "Pwhash.argon2i: salt (%d) must be \
                                   at least 8 bytes" saltlen) ;
    let work = Bigstring.create (nb_blocks * 1024) in
    argon2i buf work nb_iter password salt ;
    buflen
end

type secret
type public

module DH = struct
  external neuterize : Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_crypto_key_exchange_public_key" [@@noalloc]

  external exchange : Bigstring.t -> Bigstring.t -> Bigstring.t -> int =
    "caml_monocypher_crypto_key_exchange" [@@noalloc]

  type shared
  type _ key =
    | K  : Bigstring.t -> shared key
    | Sk : Bigstring.t -> secret key
    | Pk : Bigstring.t -> public key

  let bytes = 32

  let buffer : type a. a key -> Bigstring.t = function
    | K  buf -> buf
    | Sk buf -> buf
    | Pk buf -> buf

  let wipe : type a. a key -> unit = function
    | K  buf -> wipe buf
    | Sk buf -> wipe buf
    | Pk buf -> wipe buf

  let equal : type a. a key -> a key -> bool = fun a b ->
    match a, b with
    | K a, K b -> Bigstring.equal a b
    | Sk a, Sk b -> Bigstring.equal a b
    | Pk a, Pk b -> Bigstring.equal a b

  let neuterize : type a. a key -> public key = function
    | K _ -> invalid_arg "DH.neuterize: shared key cannot be neuterized"
    | Pk pk -> Pk pk
    | Sk sk ->
      let pk = Bigstring.create bytes in
      neuterize pk sk ;
      Pk pk

  let sk_of_bytes ?(pos=0) buf =
    let buflen = Bigstring.length buf in
    if pos < 0 || buflen - pos < bytes then
      invalid_arg (Printf.sprintf "DH.sk_of_bytes: buffer (len = %d) \
                                   must be at least %d bytes" buflen bytes) ;
    let sk = Bigstring.create bytes in
    Bigstring.blit buf pos sk 0 bytes ;
    Sk sk

  let shared (Sk sk) (Pk pk) =
    let k = Bigstring.create bytes in
    match exchange k sk pk with
    | 0 -> Some (K k)
    | _ -> None

  let shared_exn sk pk =
    match shared sk pk with
    | None -> invalid_arg "DH.shared_exn"
    | Some k -> k

  let blit : type a. a key -> Bigstring.t -> int -> int = fun k buf pos ->
    begin match k with
    | K k -> Bigstring.blit k 0 buf pos bytes
    | Pk pk -> Bigstring.blit pk 0 buf pos bytes
    | Sk sk -> Bigstring.blit sk 0 buf pos bytes
    end ;
    bytes
end

module Box = struct
  external lock : Bigstring.t -> Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_crypto_lock" [@@noalloc]

  external unlock : Bigstring.t -> Bigstring.t -> Bigstring.t -> int =
    "caml_monocypher_crypto_lock" [@@noalloc]

  type key = Bigstring.t

  let bytes = 32
  let noncebytes = 24
  let macbytes = 16

  let key_of_bytes ?(pos=0) buf =
    let buflen = Bigstring.length buf in
    if pos < 0 || buflen - pos < bytes then
      invalid_arg (Printf.sprintf "Box.key_of_bytes: buffer (len = %d) must be at \
                                   least %d bytes" buflen bytes) ;
    let k = Bigstring.create bytes in
    Bigstring.blit buf pos k 0 bytes ;
    k

  let wipe k = wipe k

  let lock ~key ~nonce buf =
    lock buf key nonce

  let unlock ~key ~nonce buf =
    match unlock buf key nonce with
    | 0 -> true
    | _ -> false
end

module Sign = struct
  external neuterize : Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_crypto_sign_public_key" [@@noalloc]

  external sign :
    Bigstring.t -> Bigstring.t -> Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_crypto_sign" [@@noalloc]

  external check : Bigstring.t -> Bigstring.t -> Bigstring.t -> int =
    "caml_monocypher_crypto_check" [@@noalloc]

  type _ key =
    | Sk : Bigstring.t -> secret key
    | Pk : Bigstring.t -> public key

  let equal : type a. a key -> a key -> bool = fun a b ->
    match a, b with
    | Sk a, Sk b -> Bigstring.equal a b
    | Pk a, Pk b -> Bigstring.equal a b

  let buffer : type a. a key -> Bigstring.t = function
    | Sk buf -> buf
    | Pk buf -> buf

  let wipe : type a. a key -> unit = function
    | Sk buf -> wipe buf
    | Pk buf -> wipe buf

  let bytes = 64
  let skbytes = 32
  let pkbytes = 32

  let sk_of_bytes ?(pos=0) buf =
    let buflen = Bigstring.length buf in
    if pos < 0 || buflen - pos < skbytes then
      invalid_arg (Printf.sprintf "Sign.sk_of_bytes: buffer (len = %d) \
                                   must be at least %d bytes" buflen skbytes) ;
    let sk = Bigstring.create skbytes in
    Bigstring.blit buf pos sk 0 skbytes ;
    Sk sk

  let blit : type a. a key -> Bigstring.t -> int -> int = fun k buf pos ->
    begin match k with
    | Sk sk -> Bigstring.blit sk 0 buf pos skbytes ; skbytes
    | Pk pk -> Bigstring.blit pk 0 buf pos pkbytes ; pkbytes
    end

  let neuterize : type a. a key -> public key = function
    | Pk pk -> Pk pk
    | Sk sk ->
      let pk = Bigstring.create pkbytes in
      neuterize pk sk ;
      Pk pk

  let sign ~pk:(Pk pk) ~sk:(Sk sk) ~msg signature =
    let siglen = Bigstring.length signature in
    if siglen < bytes then
      invalid_arg (Printf.sprintf "Sign.sign: signature buffer (len = \
                                   %d) must be at least %d bytes" siglen bytes) ;
    sign signature sk pk msg ;
    bytes

  let check ~pk:(Pk pk) ~msg signature =
    let siglen = Bigstring.length signature in
    if siglen < bytes then
      invalid_arg (Printf.sprintf "Sign.check: signature buffer (len = \
                                   %d) must be at least %d bytes" siglen bytes) ;
    match check signature pk msg with
    | 0 -> true
    | _ -> false
end

module Ed25519 = struct
  type t = Bigstring.t

  let bytes = 32
  let fe_bytes = 10 * 4
  let ge_bytes = 4 * fe_bytes

  external of_bytes : Bigstring.t -> Bigstring.t -> int =
    "caml_monocypher_ge_frombytes" [@@noalloc]

  external to_bytes : Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_ge_tobytes" [@@noalloc]

  let of_pk (Sign.Pk pk) =
    let ge = Bigstring.create ge_bytes in
    ignore (of_bytes ge pk) ;
    ge

  let of_bytes buf =
    let ge = Bigstring.create ge_bytes in
    match of_bytes ge buf with
    | 0 -> Some ge
    | _ -> None

  let blit ge buf =
    let buflen = Bigstring.length buf in
    if buflen < bytes then
      invalid_arg (Printf.sprintf "Ed25519.blit: output buffer (len = \
                                   %d) must be at least %d bytes" buflen bytes) ;
    to_bytes buf ge ;
    bytes

  let to_bytes ge =
    let buf = Bigstring.create bytes in
    ignore (blit ge buf) ;
    buf

  external add : t -> t -> t -> unit =
    "caml_monocypher_ge_add" [@@noalloc]

  external scalarmult : t -> t -> Bigstring.t -> unit =
    "caml_monocypher_ge_scalarmult" [@@noalloc]

  external scalarmult_base : t -> Bigstring.t -> unit =
    "caml_monocypher_ge_scalarmult_base" [@@noalloc]

  let add p q =
    let ge = Bigstring.create ge_bytes in
    add ge p q ;
    ge

  let blit_z z buf =
    Bigstring.fill buf '\x00' ;
    if Z.sign z < 1 || Z.numbits z > 256 then
      invalid_arg (Format.asprintf "blit_z: argument (%a) must be \
                                    positive and less than 2^256" Z.pp_print z);
    let bits = Z.to_bits z in
    Bigstring.blit_of_string bits 0 buf 0 (String.length bits)

  let scalarmult p z =
    let ge = Bigstring.create ge_bytes in
    let z_buf = Bigstring.create 32 in
    blit_z z z_buf ;
    scalarmult ge p z_buf ;
    ge

  let scalarmult_base z =
    let ge = Bigstring.create ge_bytes in
    let z_buf = Bigstring.create 32 in
    blit_z z z_buf ;
    scalarmult_base ge z_buf ;
    ge
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
