#net_sync
This is a pure-rust asynchronous network synchronization crate (using tokio) that recreates familiar asynchronous paradigms but in a network context.

Let `A` and `B` be two nodes with a pre-established ordered+reliable connection to each other (e.g., over TCP, TLS, QUIC, etc)

- **join** Given `A` executing function `f_a -> r_a` and `B` executing function `f_b -> r_b`, return `r_a` to `A` and `r_b` to `B`
- **try_join** Given `A` executing function `f_a -> Result<r_a>` and `B` executing function `f_b -> Result<r_b>`, return `Result<r_a>` to `A` and `Result<r_b>` to `B` iff `Result<r_a> = Ok(r_a)` AND `Result<r_b> = Ok(r_b)`. A global error is returned if either one of the nodes fails
- **select** Given `A` executing function `f_a -> r_a` and `B` executing function `f_b -> r_b`, return `r_a` to `A` if `r_a` is computed first, or, return `r_b` to `B` if `r_b` is computed first
- **try_select** Given `A` executing function `f_a -> Result<r_a>` and `B` executing function `f_b -> Result<r_b>`, return `Result<r_a>` to `A` if `Result<r_a>` is computed first AND `Result<r_a> = Ok(r_a)`, or, return `Result<r_b>` to `B` if `Result<r_b>` is computed first AND `Result<r_b> = Ok(r_b)`. Returns a global error if both nodes fail.

Additionally, there is a ``sync_start`` file that allows the synchronization of two operations at approximately the same time.
Examples for every operation are in the source code under src/sync/[...]

In the future, this crate will include a ``NetMutex`` and ``NetRwLock`` abstraction