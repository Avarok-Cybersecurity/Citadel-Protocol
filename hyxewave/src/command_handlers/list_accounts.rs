use super::imports::*;
use hyxe_user::client_account::ClientNetworkAccount;

#[derive(Copy, Clone, Debug)]
enum ListType {
    All,
    Personal,
    Impersonal
}

#[derive(Debug, Default, Serialize)]
pub struct ActiveAccounts {
    #[serde(serialize_with = "string_vec")]
    cids: Vec<u64>,
    usernames: Vec<String>,
    full_names: Vec<String>,
    is_personals: Vec<bool>,
    creation_dates: Vec<String>
}

impl ActiveAccounts {
    pub fn insert(&mut self, input: (u64, String, String, bool, String)){
        self.cids.push(input.0);
        self.usernames.push(input.1);
        self.full_names.push(input.2);
        self.is_personals.push(input.3);
        self.creation_dates.push(input.4);
    }
}

pub fn handle<'a>(matches: &ArgMatches<'a>, _server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext, ffi_io: Option<FFIIO>) -> Result<Option<KernelResponse>, ConsoleError> {
    if matches.is_present("personal") {
        return if ffi_io.is_some() {
            Ok(Some(handle_ffi(ctx, ListType::Personal)))
        } else {
            list(ctx,ListType::Personal, "No personal accounts exist locally")
        }
    }

    if matches.is_present("impersonal") {
        return if ffi_io.is_some() {
            Ok(Some(handle_ffi(ctx, ListType::Impersonal)))
        } else {
            list(ctx,ListType::Impersonal, "No impersonal accounts exist locally")
        }
    }

    return if ffi_io.is_some() {
        Ok(Some(handle_ffi(ctx, ListType::All)))
    } else {
        list(ctx,ListType::All, "No accounts exist locally")
    }
}

fn list(ctx: &ConsoleContext, list_type: ListType, none_message: &str) -> Result<Option<KernelResponse>, ConsoleError> {
    let mut table = Table::new();
    table.set_titles(prettytable::row![Fgcb => "CID", "Username", "Full Name", "Personal", "Creation Date"]);
    let mut cnt = 0;

    ctx.list_all_registered_users(|cnac| {
        match list_type {
            ListType::All => {
                add_to_table(cnac, &mut table, &mut cnt)
            }

            ListType::Personal => {
                if cnac.is_personal() {
                    add_to_table(cnac, &mut table, &mut cnt)
                }
            }

            ListType::Impersonal => {
                if !cnac.is_personal() {
                    add_to_table(cnac, &mut table, &mut cnt)
                }
            }
        }
    });

    if cnt != 0 {
        printf!(table.printstd());
    } else {
        colour::yellow_ln!("{}", none_message);
    }

    Ok(None)
}

fn add_to_table(cnac: &ClientNetworkAccount, table: &mut Table, cnt: &mut usize) {
    let read = cnac.read();
    let cid = read.cid;
    let username = read.username.as_str();
    let full_name = read.full_name.as_str();
    let is_personal = read.is_local_personal;
    let creation_date = read.creation_date.as_str();

    *cnt += 1;
    table.add_row(prettytable::row![c => cid, username, full_name, is_personal, creation_date]);
}

fn handle_ffi(ctx: &ConsoleContext, list_type: ListType) -> KernelResponse {
    let mut ret = ActiveAccounts::default();
    ctx.list_all_registered_users(|cnac| {
        match list_type {
            ListType::All => {
                ret.insert(get_info(cnac))
            }

            ListType::Personal => {
                if cnac.is_personal() {
                    ret.insert(get_info(cnac))
                }
            }

            ListType::Impersonal => {
                if !cnac.is_personal() {
                    ret.insert(get_info(cnac))
                }
            }
        }
    });

    KernelResponse::DomainSpecificResponse(DomainResponse::GetAccounts(ret))
}

fn get_info(cnac: &ClientNetworkAccount) -> (u64, String, String, bool, String) {
    let read = cnac.read();
    let cid = read.cid;
    let username = read.username.as_str();
    let full_name = read.full_name.as_str();
    let is_personal = read.is_local_personal;
    let creation_date = read.creation_date.as_str();

    (cid, username.to_string(), full_name.to_string(), is_personal, creation_date.to_string())
}