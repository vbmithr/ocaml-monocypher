(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

external wipe : Bigstring.t -> int -> unit =
  "caml_monocypher_crypto_wipe" [@@noalloc]

external wipe_bytes : Bytes.t -> int -> unit =
  "caml_monocypher_crypto_wipe_bytes" [@@noalloc]

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

let wipe_bytes ?len buf =
  let buflen = Bytes.length buf in
  let len = check_len buflen len in
  wipe_bytes buf len

let wipe_string ?len buf =
  wipe_bytes ?len (Bytes.unsafe_of_string buf)

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
      final ctx buf ;
      len

    let final ctx =
      let hash = Bigstring.create (hash_size ctx) in
      final ctx hash ;
      hash

    let digest ?key len msg =
      let ctx = init ?key len in
      update ctx msg ;
      final ctx

    let blit_digest ?key len buf ~msg =
      let ctx = init ?key len in
      update ctx msg ;
      blit_final ctx buf
  end

  module SHA512 = struct
    external sizeof_ctx : unit -> int =
      "caml_monocypher_sizeof_crypto_sha512_ctx" [@@noalloc]

    external init : Bigstring.t -> unit =
      "caml_monocypher_crypto_sha512_init" [@@noalloc]

    external update : Bigstring.t -> Bigstring.t -> unit =
      "caml_monocypher_crypto_sha512_update" [@@noalloc]

    external final : Bigstring.t -> Bigstring.t -> unit =
      "caml_monocypher_crypto_sha512_final" [@@noalloc]

    type ctx = Bigstring.t

    let ctxlen = sizeof_ctx ()
    let hashlen = 64

    let init () =
      let ctx = Bigstring.create ctxlen in
      init ctx ;
      ctx

    let blit_final ctx buf =
      if Bigstring.length buf < hashlen then
        invalid_arg (Printf.sprintf "Hash.Blake2b.blit_final: buffer \
                                     is less than %d bytes" hashlen) ;
      final ctx buf ;
      hashlen

    let final ctx =
      let hash = Bigstring.create hashlen in
      final ctx hash ;
      hash

    let digest msg =
      let ctx = init () in
      update ctx msg ;
      final ctx

    let blit_digest buf ~msg =
      let ctx = init () in
      update ctx msg ;
      blit_final ctx buf
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
type extended

module DH = struct
  external neuterize : Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_crypto_key_exchange_public_key" [@@noalloc]

  external exchange : Bigstring.t -> Bigstring.t -> Bigstring.t -> unit =
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

  let copy : type a. a key -> a key = function
    | K  buf -> K (Bigstring.copy buf)
    | Sk buf -> Sk (Bigstring.copy buf)
    | Pk buf -> Pk (Bigstring.copy buf)

  let wipe : type a. a key -> unit = function
    | K  buf -> wipe buf
    | Sk buf -> wipe buf
    | Pk buf -> wipe buf

  let equal : type a. a key -> a key -> bool = fun a b ->
    match a, b with
    | K a, K b -> equal32 a b
    | Sk a, Sk b -> equal32 a b
    | Pk a, Pk b -> equal32 a b

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
    exchange k sk pk ;
    K k

  let blit : type a. a key -> Bigstring.t -> int -> int = fun k buf pos ->
    begin match k with
    | K k -> Bigstring.blit k 0 buf pos bytes
    | Pk pk -> Bigstring.blit pk 0 buf pos bytes
    | Sk sk -> Bigstring.blit sk 0 buf pos bytes
    end ;
    bytes
end

module Box = struct
  external lock :
    Bigstring.t -> Bigstring.t -> Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_crypto_lock" [@@noalloc]

  external unlock :
    Bigstring.t -> Bigstring.t -> Bigstring.t -> Bigstring.t -> int =
    "caml_monocypher_crypto_unlock" [@@noalloc]

  let keybytes = 32
  let noncebytes = 24
  let macbytes = 16

  let check_lengths key nonce mac =
    let keylen = Bigstring.length key in
    let noncelen = Bigstring.length nonce in
    let maclen = Bigstring.length mac in
    if keylen < keybytes then
      invalid_arg (Printf.sprintf "Box.{un,}lock: key must be at least %d \
                                   bytes" keylen) ;
    if noncelen < noncebytes then
      invalid_arg (Printf.sprintf "Box.{un,}lock: nonce must be at least %d \
                                   bytes" noncelen) ;
    if maclen < macbytes then
      invalid_arg (Printf.sprintf "Box.{un,}lock: mac must be at least %d \
                                   bytes" maclen)

  let lock ~key ~nonce ~mac buf =
    check_lengths key nonce mac ;
    lock mac buf key nonce

  let unlock ~key ~nonce ~mac buf =
    check_lengths key nonce mac ;
    match unlock mac buf key nonce with
    | 0 -> true
    | _ -> false
end

module Sign = struct
  external neuterize : Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_crypto_ed25519_public_key" [@@noalloc]

  external neuterize_extended : Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_crypto_sign_public_key_extended" [@@noalloc]

  external sizeof_sign_ctx : unit -> int =
    "caml_monocypher_sizeof_crypto_sign_ctx" [@@noalloc]

  external sizeof_check_ctx : unit -> int =
    "caml_monocypher_sizeof_crypto_check_ctx" [@@noalloc]

  let sign_ctx_bytes = sizeof_sign_ctx ()
  let check_ctx_bytes = sizeof_check_ctx ()

  external sign_init_first_pass :
    Bigstring.t -> Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_crypto_ed25519_sign_init_first_pass" [@@noalloc]

  external sign_init_first_pass_extended :
    Bigstring.t -> Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_crypto_ed25519_sign_init_first_pass_extended" [@@noalloc]

  external sign_init_second_pass :
    Bigstring.t -> unit =
    "caml_monocypher_crypto_ed25519_sign_init_second_pass" [@@noalloc]

  external sign_update :
    Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_crypto_ed25519_sign_update" [@@noalloc]

  external sign_final :
    Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_crypto_ed25519_sign_final" [@@noalloc]

  external check_init : Bigstring.t -> Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_crypto_ed25519_check_init" [@@noalloc]

  external check_update : Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_crypto_ed25519_check_update" [@@noalloc]

  external check_final : Bigstring.t -> int =
    "caml_monocypher_crypto_ed25519_check_final" [@@noalloc]

  type _ key =
    | Sk : Bigstring.t -> secret key
    | Pk : Bigstring.t -> public key
    | Ek : Bigstring.t -> extended key

  let equal : type a. a key -> a key -> bool = fun a b ->
    match a, b with
    | Sk a, Sk b -> equal32 a b
    | Pk a, Pk b -> equal32 a b
    | Ek a, Ek b -> equal64 a b

  let buffer : type a. a key -> Bigstring.t = function
    | Sk buf -> buf
    | Pk buf -> buf
    | Ek buf -> buf

  let length : type a. a key -> int = function
    | Sk buf -> Bigstring.length buf
    | Pk buf -> Bigstring.length buf
    | Ek buf -> Bigstring.length buf

  let copy : type a. a key -> a key = function
    | Sk buf -> Sk (Bigstring.copy buf)
    | Pk buf -> Pk (Bigstring.copy buf)
    | Ek buf -> Ek (Bigstring.copy buf)

  let wipe : type a. a key -> unit = function
    | Sk buf -> wipe buf
    | Pk buf -> wipe buf
    | Ek buf -> wipe buf

  let bytes = 64
  let skbytes = 32
  let pkbytes = 32
  let ekbytes = 64

  let unsafe_pk_of_bytes buf =
    let buflen = Bigstring.length buf in
    if buflen <> pkbytes then
      invalid_arg (Printf.sprintf "Sign.unsafe_pk_of_bytes: buffer \
                                   (len = %d) must be exactly %d bytes" buflen pkbytes) ;
    Pk buf

  let unsafe_sk_of_bytes buf =
    let buflen = Bigstring.length buf in
    if buflen <> skbytes then
      invalid_arg (Printf.sprintf "Sign.unsafe_sk_of_bytes: buffer \
                                   (len = %d) must be excatly %d bytes" buflen skbytes) ;
    Sk buf

  let unsafe_ek_of_bytes buf =
    let buflen = Bigstring.length buf in
    if buflen <> ekbytes then
      invalid_arg (Printf.sprintf "Sign.unsafe_ek_of_bytes: buffer \
                                   (len = %d) must be exactly %d bytes" buflen ekbytes) ;
    Ek buf

  let pk_of_bytes ?(pos=0) buf =
    let buflen = Bigstring.length buf in
    if pos < 0 || buflen - pos < pkbytes then
      invalid_arg (Printf.sprintf "Sign.pk_of_bytes: buffer (len = %d) \
                                   must be at least %d bytes" buflen pkbytes) ;
    let pk = Bigstring.create pkbytes in
    Bigstring.blit buf pos pk 0 pkbytes ;
    Pk pk

  let sk_of_bytes ?(pos=0) buf =
    let buflen = Bigstring.length buf in
    if pos < 0 || buflen - pos < skbytes then
      invalid_arg (Printf.sprintf "Sign.sk_of_bytes: buffer (len = %d) \
                                   must be at least %d bytes" buflen skbytes) ;
    let sk = Bigstring.create skbytes in
    Bigstring.blit buf pos sk 0 skbytes ;
    Sk sk

  let ek_of_bytes ?(pos=0) buf =
    let buflen = Bigstring.length buf in
    if pos < 0 || buflen - pos < ekbytes then
      invalid_arg (Printf.sprintf "Sign.ek_of_bytes: buffer (len = %d) \
                                   must be at least %d bytes" buflen ekbytes) ;
    let ek = Bigstring.create ekbytes in
    Bigstring.blit buf pos ek 0 ekbytes ;
    Ek ek

  let blit : type a. a key -> Bigstring.t -> int -> int = fun k buf pos ->
    begin match k with
    | Sk sk -> Bigstring.blit sk 0 buf pos skbytes ; skbytes
    | Pk pk -> Bigstring.blit pk 0 buf pos pkbytes ; pkbytes
    | Ek ek -> Bigstring.blit ek 0 buf pos ekbytes ; ekbytes
    end

  let neuterize : type a. a key -> public key = function
    | Pk pk -> Pk pk
    | Sk sk ->
      let pk = Bigstring.create pkbytes in
      neuterize pk sk ;
      Pk pk
    | Ek ek ->
      let pk = Bigstring.create pkbytes in
      neuterize_extended pk ek ;
      Pk pk

  external trim_scalar : Bigstring.t -> unit =
    "caml_monocypher_trim_scalar" [@@noalloc]

  let extend (Sk sk) =
    let ek = Hash.SHA512.digest sk in
    trim_scalar ek ;
    Ek ek

  let sign_gen ?pk ~sk g signature =
    let pk = match pk with
      | None -> neuterize sk
      | Some pk -> pk in
    let siglen = Bigstring.length signature in
    if siglen < bytes then
      invalid_arg (Printf.sprintf "Sign.sign: signature buffer (len = \
                                   %d) must be at least %d bytes" siglen bytes) ;
    let ctx = Bigstring.create sign_ctx_bytes in
    sign_init_first_pass ctx (buffer sk) (buffer pk) ;
    Gen.iter (sign_update ctx) (g ()) ;
    sign_init_second_pass ctx ;
    Gen.iter (sign_update ctx) (g ()) ;
    sign_final ctx signature ;
    bytes

  let sign ?pk ~sk ~msg signature =
    sign_gen ?pk ~sk (Gen.Restart.return msg) signature

  let sign_gen_extended ?pk ~ek g signature =
    let pk = match pk with
      | None -> neuterize ek
      | Some pk -> pk in
    let siglen = Bigstring.length signature in
    if siglen < bytes then
      invalid_arg (Printf.sprintf "Sign.sign: signature buffer (len = \
                                   %d) must be at least %d bytes" siglen bytes) ;
    let ctx = Bigstring.create sign_ctx_bytes in
    sign_init_first_pass_extended ctx (buffer ek) (buffer pk) ;
    Gen.iter (sign_update ctx) (g ()) ;
    sign_init_second_pass ctx ;
    Gen.iter (sign_update ctx) (g ()) ;
    sign_final ctx signature ;
    bytes

  let sign_extended ?pk ~ek ~msg signature =
    sign_gen_extended ?pk ~ek (Gen.Restart.return msg) signature

  let check_gen ~pk:(Pk pk) g signature =
    let siglen = Bigstring.length signature in
    if siglen < bytes then
      invalid_arg (Printf.sprintf "Sign.check: signature buffer (len = \
                                   %d) must be at least %d bytes" siglen bytes) ;
    let ctx = Bigstring.create check_ctx_bytes in
    check_init ctx signature pk ;
    Gen.iter (check_update ctx) g ;
    match check_final ctx with
    | 0 -> true
    | _ -> false

  let check ~pk ~msg signature =
    check_gen ~pk (Gen.return msg) signature
end

module Ed25519 = struct
  type t = Bigstring.t
  type cached = Bigstring.t

  let bytes = 32
  let fe_bytes = 10 * 4
  let ge_bytes = 4 * fe_bytes

  let copy = Bigstring.copy

  external cache : Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_ge_cache" [@@noalloc]

  let cache t =
    let cached = Bigstring.create ge_bytes in
    cache cached t ;
    cached

  external of_bytes : Bigstring.t -> Bigstring.t -> int =
    "caml_monocypher_ge_frombytes" [@@noalloc]

  external to_bytes : Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_ge_tobytes" [@@noalloc]

  let of_pk (Sign.Pk pk) =
    let ge = Bigstring.create ge_bytes in
    match of_bytes ge pk with
    | 0 -> ge
    | _ -> failwith "internal error"

  let to_pk t =
    let buf = Bigstring.create Sign.pkbytes in
    to_bytes buf t ;
    Sign.unsafe_pk_of_bytes buf

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

  let equal a b =
    equal32 (to_bytes a) (to_bytes b)

  external add : t -> t -> t -> unit =
    "caml_monocypher_ge_add" [@@noalloc]

  external double_scalarmult :
    t -> Bigstring.t -> Bigstring.t -> unit =
    "caml_monocypher_ge_double_scalarmult" [@@noalloc]

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
    let z1_buf = Bigstring.create 32 in
    let z2_buf = Bigstring.make 32 '\x00' in
    blit_z z z1_buf ;
    double_scalarmult p z1_buf z2_buf

  let double_scalarmult p z1 z2 =
    let z1_buf = Bigstring.create 32 in
    let z2_buf = Bigstring.create 32 in
    blit_z z1 z1_buf ;
    blit_z z2 z2_buf ;
    double_scalarmult p z1_buf z2_buf

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
