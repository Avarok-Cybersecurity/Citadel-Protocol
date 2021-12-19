use std::error::Error;
use std::ffi::OsStr;

mod definitions;
mod sql;
mod web;

const AVAROK_SQLITE_URL: &'static str = "AVAROK_SQLITE_URL";
const AVAROK_BIND_ADDR: &'static str = "AVAROK_BIND_ADDR";

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let _ = dotenv::dotenv();
    let sqlite_url = get_var(AVAROK_SQLITE_URL)?;
    let listen_addr = get_var(AVAROK_BIND_ADDR)?;
    println!("SQLite URL: {:?}", &sqlite_url);
    println!("Listen addr: {:?}", &listen_addr);

    web::WebHandler::new(sqlite_url).await?.listen(listen_addr).await?;
    Ok(())
}

fn get_var<K: AsRef<OsStr>>(input: K) -> Result<String, Box<dyn Error>> {
    let out = std::env::var(&input)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, format!("Environmental variable '{:?}' not found", input.as_ref())))?;
    Ok(out)
}