# HyperBuf
A dynamic and highly optimized buffer with atomic locking mechanisms and asynchronous memory management (async/await ready; use nightly!)

HyperBuf is about 40% faster than BytesMut, and 11% faster than std::vec!

For memory retrieval, instead of spin-waiting and blocking the thread, the system uses an atomically-backed and asynchronous model that has the capacity to treat the data internally as any arbitrary type (Type system pending). This is especially useful for writing a stream of network bytes to a custom Packet type.

There are three ways to interact with the data, and it is up to the programmer to make the wisest decisions:

1. Direct treatment of the system as a u8 buffer, or;

2. Asynchronous casting of type to an immutable yet readable version (via ReadVisitors), or;

3. Asynchronous casting of type to a mutable thus writable version (via WriteVisitor's)

The rule for consistency is simple: if you choose to treat the type as a buffer, you should NOT use Write/Read Visitors. However, keep in mind that, for performance reasons, this check is NOT made programatically! It is up to YOU to design your program correctly around this model

When you use a WriteVisitor, you should specify the amount of bytes you plan on writing when calling visit(). If you don't plan on making the type grow, you can simply enter None.

``

    // Load some random data into a struct
    let i0 = Txx::new(0);
    let i1 = Txx::new(1);
    let i2 = Txx::new(10);

    let items = &[i0, i1, i2];
    // Wrap around the array
    let mut wrapper = HyperVec::wrap(items);

    // For demonstration purposes, we'll count the bytes in the structures
    let mut byte_count = 0;
    for item in items {
        byte_count += std::mem::size_of_val(item);
    }

    println!("Byte count (u8s): {}", byte_count);
    let writer = wrapper.cast_mut::<Txx>().unwrap();
    let reader = wrapper.cast::<u8>().unwrap();

    rayon::scope(move |sc| {
        sc.spawn(|sc2| {
            thread::sleep(Duration::from_millis(100));
            block_on(reader.visit(|mut reader| {
                let bytes = reader.read_array().unwrap();
                println!("READ: {}", bytes[0]);
                Ok(reader)
            })).unwrap();
        });

        sc.spawn(move |sc2| {
            // If we expect to add data, we can pre-allocate bytes. If we are just editing data, with no additional bytes, we can enter "None".
            // In this case, we are pre-allocating enough space for
            block_on(writer.visit(Some(std::mem::size_of::<Txx>()), |mut writer| {
                // DO NOT BLOCK HEREIN
                let objects: &mut [Txx] = writer.write_array().unwrap();
                assert_eq!(objects.len(), items.len());

                writer.append(Txx::new(100));
                writer.append_all(items);

                let objects: &mut [Txx] = writer.write_array().unwrap();
                assert_eq!(items.len()*2 + 1, objects.len());

                let bytes = writer.write_bytes().unwrap(); // I can declare the initial WriteVisitor to have type Txx, but it is not necessarily bound to that alone!
                // Below, we return the number of bytes written as well as the passing of ownership of the WriteVisitor instance
                Ok((writer.bytes_written(), writer))
            })).unwrap();
        });

    });
``
When using indexes or the put_u8-like methods, HyperVec is faster than the std::vec, and faster than BytesMut:


```

[System Information]
    Operating System: Windows 10 Enterprise Insider Preview 64-bit (10.0, Build 18917) (18917.rs_prerelease.190607-1942)
    BIOS: 1301 (type: UEFI)
    Processor: Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz (8 CPUs), ~4.2GHz
    Memory: 16384MB RAM
    Available OS Memory: 16326MB RAM
    Page File: 15402MB used, 8859MB available

Vec benches/std vec     time:   [19.311 ns 19.317 ns 19.322 ns]
                        change: [-0.0808% -0.0337% +0.0096%] (p = 0.15 > 0.05)
                        No change in performance detected.
Found 4 outliers among 100 measurements (4.00%)
  1 (1.00%) low mild
  3 (3.00%) high mild
Vec benches/HyperVec    time:   [17.464 ns 17.480 ns 17.498 ns]
                        change: [+0.4541% +0.6362% +0.7789%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 12 outliers among 100 measurements (12.00%)
  4 (4.00%) high mild
  8 (8.00%) high severe
Vec benches/BytesMut    time:   [24.262 ns 24.276 ns 24.290 ns]
                        change: [-0.3091% -0.2340% -0.1585%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 3 outliers among 100 measurements (3.00%)
  1 (1.00%) low mild
  2 (2.00%) high severe

```
