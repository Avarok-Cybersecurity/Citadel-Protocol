use std::error::Error;
use std::ffi::OsStr;
use std::str::FromStr;

mod definitions;
mod sql;
mod web;
mod github;

mod de;

const AVAROK_SQLITE_URL: &'static str = "AVAROK_SQLITE_URL";
const AVAROK_BIND_ADDR: &'static str = "AVAROK_BIND_ADDR";
const AVAROK_GITHUB_APP_ID: &'static str = "AVAROK_GITHUB_APP_ID";
const AVAROK_GITHUB_APP_SECRET: &'static str = "AVAROK_GITHUB_APP_SECRET";
const AVAROK_GITHUB_ORGANIZATION_NAME: &'static str = "AVAROK_GITHUB_ORGANIZATION_NAME";

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let _ = dotenv::dotenv();
    let sqlite_url = get_var(AVAROK_SQLITE_URL)?;
    let listen_addr = get_var(AVAROK_BIND_ADDR)?;
    let github_organization_name = get_var(AVAROK_GITHUB_ORGANIZATION_NAME)?;
    let github_app_id = u64::from_str(&get_var(AVAROK_GITHUB_APP_ID)?)?;
    let github_app_secret = async_std::fs::read(get_var(AVAROK_GITHUB_APP_SECRET)?).await?;

    println!("SQLite URL: {:?}", &sqlite_url);
    println!("Listen addr: {:?}", &listen_addr);
    println!("Github organization name: {:?}", &github_organization_name);
    println!("Github App ID: {:?}", &github_app_id);
    println!("Github App Secret: {:?}", &github_app_secret);

    let gh = github::GithubHandler::new(github_app_id, &github_app_secret, github_organization_name).await?;
    web::WebHandler::new(sqlite_url, gh).await?.listen(listen_addr).await?;

    Ok(())
}

fn get_var<K: AsRef<OsStr>>(input: K) -> Result<String, Box<dyn Error>> {
    let out = std::env::var(&input)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, format!("Environmental variable '{:?}' not found", input.as_ref())))?;
    Ok(out)
}