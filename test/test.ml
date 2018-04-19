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

let rand = [
  "Rand.gen", `Quick, test_rand_gen ;
  "Rand.write", `Quick, test_rand_write ;
  "wipe", `Quick, test_wipe ;
  "equal16", `Quick, test_equal16 ;
  "equal32", `Quick, test_equal16 ;
  "equal64", `Quick, test_equal16 ;
]

let () =
  Alcotest.run "monocypher" [
    "rand", rand ;
  ]
