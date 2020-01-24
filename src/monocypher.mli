(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

(** {1 Memory Wipe} *)

val wipe : ?len:int -> Bigstring.t -> unit
val wipe_bytes : ?len:int -> Bytes.t -> unit
val wipe_string : ?len:int -> String.t -> unit

(** {1 Constant Time Comparison} *)

val equal16 : Bigstring.t -> Bigstring.t -> bool
val equal32 : Bigstring.t -> Bigstring.t -> bool
val equal64 : Bigstring.t -> Bigstring.t -> bool

(** {1 Random Number Generation } *)

module Rand : sig
  val gen : int -> Bigstring.t
  val write : ?len:int -> Bigstring.t -> int
end

module Hash : sig
  module Blake2b : sig
    type ctx
    (** Type of a Blake2b context. Gets wiped after a call to
        [blit_final] or [final]. *)

    val init : ?key:Bigstring.t -> int -> ctx
    val update : ctx -> Bigstring.t -> unit
    val blit_final : ctx -> Bigstring.t -> int
    val final : ctx -> Bigstring.t

    val digest :
      ?key:Bigstring.t -> int -> Bigstring.t -> Bigstring.t
    val blit_digest :
      ?key:Bigstring.t -> int -> Bigstring.t -> msg:Bigstring.t -> int
  end

  module SHA512 : sig
    type ctx
    (** Type of a SHA512 context. Gets wiped after a call to
        [blit_final] or [final]. *)

    val init : unit -> ctx
    val update : ctx -> Bigstring.t -> unit
    val blit_final : ctx -> Bigstring.t -> int
    val final : ctx -> Bigstring.t

    val digest : Bigstring.t -> Bigstring.t
    val blit_digest : Bigstring.t -> msg:Bigstring.t -> int
  end
end

module Pwhash : sig
  val argon2i :
    ?nb_blocks:int -> ?nb_iter:int ->
    password:Bigstring.t -> salt:Bigstring.t -> Bigstring.t -> int
end

type secret
type public
type extended

module DH : sig
  type shared
  type _ key

  val bytes : int
  val equal : 'a key -> 'a key -> bool
  val copy : 'a key -> 'a key
  val sk_of_bytes : ?pos:int -> Bigstring.t -> secret key
  val neuterize : _ key -> public key
  val shared : secret key -> public key -> shared key
  val wipe : _ key -> unit

  val buffer : _ key -> Bigstring.t
  (** [buffer k] is [k]'s internal buffer. DO NOT MODIFY. *)

  val blit : _ key -> Bigstring.t -> int -> int
end

module Box : sig
  val keybytes : int
  val noncebytes : int
  val macbytes : int

  val lock :
    key:Bigstring.t -> nonce:Bigstring.t -> mac:Bigstring.t -> Bigstring.t -> unit
  val unlock :
    key:Bigstring.t -> nonce:Bigstring.t -> mac:Bigstring.t -> Bigstring.t -> bool
end

module Sign : sig
  type _ key

  val bytes : int
  val skbytes : int
  val pkbytes : int

  val equal : 'a key -> 'a key -> bool
  val buffer : _ key -> Bigstring.t
  (** [buffer k] is [k]'s internal buffer. DO NOT MODIFY. *)

  val length : _ key -> int

  val copy : 'a key -> 'a key
  val wipe : _ key -> unit

  val unsafe_pk_of_bytes : Bigstring.t -> public key
  val unsafe_sk_of_bytes : Bigstring.t -> secret key
  val unsafe_ek_of_bytes : Bigstring.t -> extended key

  val pk_of_bytes : ?pos:int -> Bigstring.t -> public key
  val sk_of_bytes : ?pos:int -> Bigstring.t -> secret key
  val ek_of_bytes : ?pos:int -> Bigstring.t -> extended key

  val neuterize : _ key -> public key
  val extend : secret key -> extended key

  val blit : _ key -> Bigstring.t -> int -> int

  val sign :
    ?pk:public key -> sk:secret key -> msg:Bigstring.t -> Bigstring.t -> int

  val sign_gen :
    ?pk:public key -> sk:secret key -> Bigstring.t Gen.Restart.t -> Bigstring.t -> int

  val sign_extended :
    ?pk:public key -> ek:extended key -> msg:Bigstring.t -> Bigstring.t -> int

  val sign_gen_extended :
    ?pk:public key -> ek:extended key -> Bigstring.t Gen.Restart.t -> Bigstring.t -> int

  val check :
    pk:public key -> msg:Bigstring.t -> Bigstring.t -> bool

  val check_gen :
    pk:public key -> Bigstring.t Gen.t -> Bigstring.t -> bool
end

module Ed25519 : sig
  type t
  (** Type of a point on the Ed25519 curve. *)

  type cached
  (** Type of a point on the Ed25519 curve, cached representation. *)

  val cache : t -> cached
  (** [cached t] is [t] in cached representation. *)

  val equal : t -> t -> bool
  (** [equal a b] is [true] if [to_bytes a] = [to_bytes b], [false]
      otherwise. *)

  val bytes : int
  val copy : t -> t

  val of_pk : public Sign.key -> t
  val to_pk : t -> public Sign.key

  val of_bytes : Bigstring.t -> t option
  (** [of_bytes buf] is [Some t] iff [buf] is at least 32 bytes long
      and whose first 32 bytes is a valid compressed serialization of a
      point, and [None] otherwise. *)

  val blit : t -> Bigstring.t -> int
  (** [blit t buf] blits the compressed serialization of [t] in [buf]
      and returns [32], the length of a compressed point. *)

  val to_bytes : t -> Bigstring.t
  (** [to_bytes t] is a freshly allocated buffer with [t]'s
      serialization in it. *)

  val add : t -> cached -> t
  val scalarmult : t -> Z.t -> unit

  val double_scalarmult : t -> Z.t -> Z.t -> unit
  (** [double_scalarmult t a b] is [at + bB] where B is the curve's
      base point. *)

  val scalarmult_base : Z.t -> t
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
