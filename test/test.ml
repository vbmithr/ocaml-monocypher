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

let rand = [
  "gen", `Quick, test_rand_gen ;
  "write", `Quick, test_rand_write ;
]

let () =
  Alcotest.run "monocypher" [
    "rand", rand ;
  ]
