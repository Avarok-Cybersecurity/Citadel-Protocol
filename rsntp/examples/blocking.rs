fn main() {
    let client = rsntp::SntpClient::new();
    let time_info = client.synchronize("pool.ntp.org").unwrap();

    println!(
        "Clock offset: {} ms",
        time_info.clock_offset().num_milliseconds()
    );
    println!(
        "Round trip delay: {} ms",
        time_info.round_trip_delay().num_milliseconds()
    );
    println!("Server timestamp: {}", time_info.datetime().to_string());

    println!(
        "Reference identifier: {}",
        time_info.reference_identifier().to_string()
    );
    println!("Stratum: {}", time_info.stratum());
}
