use super::imports::*;
use hyxe_user::misc::CNACMetadata;

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

pub async fn handle<'a>(matches: &ArgMatches<'a>, _server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext, ffi_io: Option<FFIIO>) -> Result<Option<KernelResponse>, ConsoleError> {
    let limit = if let Some(limit) = matches.value_of("limit") {
        Some(i32::from_str(limit)?)
    } else {
        None
    };

    if matches.is_present("personal") {
        return if ffi_io.is_some() {
            handle_ffi(ctx, ListType::Personal, limit).await
        } else {
            list(ctx,ListType::Personal, "No personal accounts exist locally", limit).await
        }
    }

    if matches.is_present("impersonal") {
        return if ffi_io.is_some() {
            handle_ffi(ctx, ListType::Impersonal, limit).await
        } else {
            list(ctx,ListType::Impersonal, "No impersonal accounts exist locally", limit).await
        }
    }

    return if ffi_io.is_some() {
        handle_ffi(ctx, ListType::All, limit).await
    } else {
        list(ctx,ListType::All, "No accounts exist locally", limit).await
    }
}

async fn list(ctx: &ConsoleContext, list_type: ListType, none_message: &str, limit: Option<i32>) -> Result<Option<KernelResponse>, ConsoleError> {
    let mut table = Table::new();

    table.set_titles(prettytable::row![Fgcb => "CID", "Username", "Full Name", "Personal", "Creation Date"]);
    let mut cnt = 0;

    let users = ctx.list_all_registered_users(limit).await?;
    for user in users {
        match list_type {
            ListType::All => {
                add_to_table(user, &mut table, &mut cnt)
            }

            ListType::Personal => {
                if user.is_personal {
                    add_to_table(user, &mut table, &mut cnt)
                }
            }

            ListType::Impersonal => {
                if !user.is_personal {
                    add_to_table(user, &mut table, &mut cnt)
                }
            }
        }
    }

    if cnt != 0 {
        printf!(table.printstd());
    } else {
        colour::yellow_ln!("{}", none_message);
    }

    Ok(None)
}

fn add_to_table(metadata: CNACMetadata, table: &mut Table, cnt: &mut usize) {
    let cid = metadata.cid;
    let username = metadata.username.as_str();
    let full_name = metadata.full_name.as_str();
    let is_personal = metadata.is_personal;
    let creation_date = metadata.creation_date.as_str();

    *cnt += 1;
    table.add_row(prettytable::row![c => cid, username, full_name, is_personal, creation_date]);
}

async fn handle_ffi(ctx: &ConsoleContext, list_type: ListType, limit: Option<i32>) -> Result<Option<KernelResponse>, ConsoleError> {
    let mut ret = ActiveAccounts::default();
    let users = ctx.list_all_registered_users(limit).await?;
    for user in users {
        match list_type {
            ListType::All => {
                ret.insert(get_info(user))
            }

            ListType::Personal => {
                if user.is_personal {
                    ret.insert(get_info(user))
                }
            }

            ListType::Impersonal => {
                if !user.is_personal {
                    ret.insert(get_info(user))
                }
            }
        }
    }

    Ok(Some(KernelResponse::DomainSpecificResponse(DomainResponse::GetAccounts(ret))))
}

fn get_info(metadata: CNACMetadata) -> (u64, String, String, bool, String) {
    let cid = metadata.cid;
    let username = metadata.username;
    let full_name = metadata.full_name;
    let is_personal = metadata.is_personal;
    let creation_date = metadata.creation_date;

    (cid, username, full_name, is_personal, creation_date)
}