# quantum_random
**A fully asynchronous quantum-random generator**

Credit goes to qrng.anu.edu.au for the source of quantum-random data

The ANU rng is a nearly perfect random number generator. I take the data and mix it with the rand rng library to help increase entropy in the case that the HTTPS download stream is comprimised remotely; in that case, the data would be modified based on local parameters anyways, and as such, wouldn't matter if the data is comprimised remotely.

The ANU API limits requests to 1024 random numbers at a time per connection*. This program allows you to retrieve more than that (millions even).

```
use futures::executor::block_on;
use quantum_random::prelude::*;

fn example() {
    let number_to_get = 11000;
    match block_on(next_u128s(number_to_get)) {
        Ok(vals) => {
            for val in vals.iter().enumerate() {
                println!("[{}]: {}", val.0, val.1);
            }
            assert_eq!(vals.len(), number_to_get);
        },
        Err(err) => {
            err.printf();
        }
    }
}
```

You may view my website here: https://thomaspbraun.com/
