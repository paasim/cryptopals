use cryptopals::dh::{get_privkey_from_rem, get_privkey_mod_from_crt, subgroups};
use num_bigint::{BigUint, RandBigInt};

fn ex58() {
    let mut rng = rand::thread_rng();
    let p = &BigUint::parse_bytes(b"11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623", 10).expect("not a number");
    let g = &BigUint::parse_bytes(b"622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357", 10).expect("not a number");
    let q = &BigUint::parse_bytes(b"335062023296420808191071248367701059461", 10)
        .expect("not a number");
    let subs = subgroups(&p, &q, 22, &mut rng);
    let privkey = rng.gen_biguint_range(&2u8.into(), q);
    let sign = |msg: &BigUint| msg.modpow(&privkey, &p);
    let (n, r) = &get_privkey_mod_from_crt(&subs, p, sign).expect("mod not found");
    let pk = get_privkey_from_rem(p, q, g, &sign(g), n, r).expect("pk not found");
    println!("privkey:  {}", privkey);
    println!("inferred: {}", pk);
}

fn main() {
    ex58()
}
