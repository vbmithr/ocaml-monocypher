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
]

let () =
  Alcotest.run "monocypher" [
    "basic", basic ;
  ]
