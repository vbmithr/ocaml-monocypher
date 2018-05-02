open Monocypher

let test_rand_gen () =
  let buflen = 1024 in
  let b = Rand.gen buflen in
  Alcotest.(check int "Rand.gen 1024" 1024 (Bigstring.length b))

let test_rand_write () =
  let buflen = 32 in
  let b = Bigstring.create buflen in
  let nb_written = Rand.write b in
  Alcotest.(check int "Rand.write b(32)" buflen nb_written) ;
  let nb_written = Rand.write ~len:16 b in
  Alcotest.(check int "Rand.write b(16)" 16 nb_written)

let test_wipe () =
  let buflen = 32 in
  let b = Rand.gen buflen in
  let bc = Bigstring.copy b in
  wipe b ;
  Alcotest.(check bool "wipe" false (Bigstring.equal b bc))

let test_equal f dim =
  let a = Rand.gen dim in
  let b = Rand.gen dim in
  let a' = Bigstring.copy a in
  Alcotest.(check bool "equal" true (f a a')) ;
  Alcotest.(check bool "not equal" false (f a b))

let test_equal16 () = test_equal equal16 16
let test_equal32 () = test_equal equal32 32
let test_equal64 () = test_equal equal64 64

let bigstring =
  Alcotest.testable Bigstring.print Bigstring.equal

let msg =
  Cstruct.to_bigarray @@ Hex.to_cstruct (`Hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f90919293949596979899")
let expected_hash =
  Cstruct.to_bigarray @@ Hex.to_cstruct (`Hex "84b154ed29bbedefa648286839046f4b5aa34430e2d67f7496e4c39f2c7ea78995f69e1292200016f16ac3b37700e6c7e7861afc396b64a59a1dbf47a55c4bbc")

let msg_key =
  Cstruct.to_bigarray @@ Hex.to_cstruct (`Hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081")
let msg_key_key =
  Cstruct.to_bigarray @@ Hex.to_cstruct (`Hex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
let expected_hash_key =
  Cstruct.to_bigarray @@ Hex.to_cstruct (`Hex "12cd1674a4488a5d7c2b3160d2e2c4b58371bedad793418d6f19c6ee385d70b3e06739369d4df910edb0b0a54cbff43d54544cd37ab3a06cfa0a3ddac8b66c89")

let test_blake2b () =
  let hash_size = 64 in
  let ctx = Hash.Blake2b.init hash_size in
  Hash.Blake2b.update ctx msg ;
  let hash = Hash.Blake2b.final ctx in
  Alcotest.check bigstring "final" expected_hash hash

let test_blake2b_blit () =
  let hash_size = 64 in
  let ctx = Hash.Blake2b.init hash_size in
  Hash.Blake2b.update ctx msg ;
  let hash = Bigstring.create hash_size in
  let nb_written = Hash.Blake2b.blit_final ctx hash in
  Alcotest.check bigstring "final" expected_hash hash ;
  Alcotest.(check int "bytes_written" hash_size nb_written)

let test_blake2b_key () =
  let hash_size = 64 in
  let ctx = Hash.Blake2b.init ~key:msg_key_key hash_size in
  Hash.Blake2b.update ctx msg_key ;
  let hash = Hash.Blake2b.final ctx in
  Alcotest.check bigstring "final" expected_hash_key hash

let test_argon2i () =
  let password = Rand.gen 10 in
  let salt = Rand.gen 16 in
  let hashlen = 64 in
  let hash = Bigstring.create hashlen in
  let nb_written = Pwhash.argon2i ~password ~salt hash in
  Alcotest.(check int "argon2i" hashlen nb_written)

let test_dh () =
  let sk = DH.sk_of_bytes (Rand.gen DH.bytes) in
  let sk2 = DH.sk_of_bytes (Rand.gen DH.bytes) in
  let pk = DH.neuterize sk in
  let pk2 = DH.neuterize sk2 in
  let k = DH.shared_exn sk pk2 in
  let k2 = DH.shared_exn sk2 pk in
  Alcotest.(check bool "dh" true DH.(equal k k2))

let test_box () =
  let sk = DH.sk_of_bytes (Rand.gen DH.bytes) in
  let sk2 = DH.sk_of_bytes (Rand.gen DH.bytes) in
  let pk2 = DH.neuterize sk2 in
  let k = DH.shared_exn sk pk2 in
  let k = DH.buffer k in
  let key = Box.key_of_bytes k in
  let msg = Bigstring.of_string "Voulez-vous coucher avec moi, ce soir ?" in
  let msglen = Bigstring.length msg in
  let buf = Bigstring.init (msglen + Box.macbytes) (fun _ -> '\x00') in
  let nonce = Rand.gen Box.noncebytes in
  Bigstring.blit msg 0 buf Box.macbytes msglen ;
  Box.lock ~key ~nonce buf ;
  let res = Box.unlock ~key ~nonce buf in
  Alcotest.(check bool "box decoded ok" true res) ;
  Alcotest.(check bigstring "msg ok" msg (Bigstring.sub buf Box.macbytes msglen))

let test_sign () =
  let sk = Rand.gen Sign.skbytes in
  let sk = Sign.sk_of_bytes sk in
  let pk = Sign.neuterize sk in
  let msg = Bigstring.of_string "Voulez-vous coucher avec moi, ce soir ?" in
  let signature = Bigstring.create Sign.bytes in
  let nb_written = Sign.sign ~pk ~sk ~msg signature in
  Alcotest.(check int "sign nb written" Sign.bytes nb_written) ;
  Alcotest.(check bool "sign check" true (Sign.check ~pk ~msg signature)) ;
  ()

let test_comm () =
  let pk = Ed25519.of_pk Sign.(neuterize (sk_of_bytes (Rand.gen skbytes))) in
  let pk2 = Ed25519.of_pk Sign.(neuterize (sk_of_bytes (Rand.gen skbytes))) in
  let pk3 = Ed25519.add pk pk2 in
  let pk3' = Ed25519.add pk2 pk in
  Alcotest.check bigstring "commutativity"
    (Ed25519.to_bytes pk3) (Ed25519.to_bytes pk3')

let test_assoc () =
  let pk = Ed25519.of_pk Sign.(neuterize (sk_of_bytes (Rand.gen skbytes))) in
  let pk2 = Ed25519.of_pk Sign.(neuterize (sk_of_bytes (Rand.gen skbytes))) in
  let pk3 = Ed25519.of_pk Sign.(neuterize (sk_of_bytes (Rand.gen skbytes))) in
  let sum12 = Ed25519.(add pk pk2) in
  let sum23 = Ed25519.(add pk2 pk3) in
  let a = Ed25519.add sum12 pk3 in
  let b = Ed25519.add pk sum23 in
  Alcotest.check bigstring "associativity"
    (Ed25519.to_bytes a) (Ed25519.to_bytes b)

let test_arith () =
  let pk = Ed25519.of_pk Sign.(neuterize (sk_of_bytes (Rand.gen skbytes))) in
  let pk2 = Ed25519.scalarmult pk (Z.of_int 3) in
  let pk2' = Ed25519.(add (add pk pk) pk) in
  Alcotest.check bigstring "arith"
    (Ed25519.to_bytes pk2) (Ed25519.to_bytes pk2')

let test_arith2 () =
  let a = Ed25519.scalarmult_base (Z.of_int 3) in
  let b = Ed25519.scalarmult a (Z.of_int 2) in
  let b' = Ed25519.scalarmult_base (Z.of_int 6) in
  Alcotest.check bigstring "arith2"
    (Ed25519.to_bytes b) (Ed25519.to_bytes b')

let basic = [
  "Rand.gen", `Quick, test_rand_gen ;
  "Rand.write", `Quick, test_rand_write ;
  "wipe", `Quick, test_wipe ;
  "equal16", `Quick, test_equal16 ;
  "equal32", `Quick, test_equal16 ;
  "equal64", `Quick, test_equal16 ;
  "blake2b", `Quick, test_blake2b ;
  "blake2b_blit", `Quick, test_blake2b_blit ;
  "blake2b_key", `Quick, test_blake2b_key ;
  "argon2i", `Quick, test_argon2i ;
  "dh", `Quick, test_dh ;
  "box", `Quick, test_box ;
  "sign", `Quick, test_sign ;
  "commutativity", `Quick, test_comm ;
  "associativity", `Quick, test_assoc ;
  "arith", `Quick, test_arith ;
  "arith2", `Quick, test_arith2 ;
]

let () =
  Alcotest.run "monocypher" [
    "basic", basic ;
  ]
