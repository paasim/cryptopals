use cryptopals::prime::mr_prime;

fn ex() {
    for _ in 0..100 {
        //let _ = mr_prime(1024, 20);
        println!("{}", mr_prime(16, 20));
    }
}

fn main() {
    ex()
}
