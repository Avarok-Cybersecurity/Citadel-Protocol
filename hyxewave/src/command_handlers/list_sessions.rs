use super::imports::*;

#[derive(Copy, Clone, Debug)]
enum ListType {
    All,
    Personal,
    Impersonal
}

#[derive(Debug, Default, Serialize)]
pub struct ActiveSessions {
    usernames: Vec<String>,
    #[serde(serialize_with = "string_vec")]
    cids: Vec<u64>,
    endpoints: Vec<String>,
    is_personals: Vec<bool>,
    #[serde(serialize_with = "string_vec")]
    runtime_sec: Vec<u64>
}

impl ActiveSessions {
    pub fn insert(&mut self, input: (&String, u64, String, bool, u64)) {
        self.usernames.push(input.0.clone());
        self.cids.push(input.1);
        self.endpoints.push(input.2);
        self.is_personals.push(input.3);
        self.runtime_sec.push(input.4);
    }
}

pub async fn handle<'a>(matches: &ArgMatches<'a>, _server_remote: &'a HdpServerRemote, ctx: &'a ConsoleContext, ffi_io: Option<FFIIO>) -> Result<Option<KernelResponse>, ConsoleError> {
    if matches.is_present("personal") {
        return if ffi_io.is_some() {
            Ok(Some(handle_ffi(ctx, ListType::Personal).await))
        } else {
            list(ctx,ListType::Personal, "No personal sessions active").await
        }
    }

    if matches.is_present("impersonal") {
        return if ffi_io.is_some() {
            Ok(Some(handle_ffi(ctx, ListType::Impersonal).await))
        } else {
            list(ctx,ListType::Impersonal, "No impersonal sessions active").await
        }
    }

    return if ffi_io.is_some() {
        Ok(Some(handle_ffi(ctx, ListType::All).await))
    } else {
        list(ctx,ListType::All, "No sessions active").await
    }
}

async fn list(ctx: &ConsoleContext, list_type: ListType, none_message: &str) -> Result<Option<KernelResponse>, ConsoleError> {
    let mut table = Table::new();
    table.set_titles(prettytable::row![Fgcb => "Username", "CID", "Address", "Personal", "Runtime(s)"]);
    let mut cnt = 0;

    ctx.list_all_sessions(|sess| {
        match list_type {
            ListType::All => {
                add_to_table(sess, &mut table, &mut cnt)
            }

            ListType::Personal => {
                if sess.is_personal {
                    add_to_table(sess, &mut table, &mut cnt)
                }
            }

            ListType::Impersonal => {
                if !sess.is_personal {
                    add_to_table(sess, &mut table, &mut cnt)
                }
            }
        }
    }).await;

    if cnt != 0 {
        printf!(table.printstd());
    } else {
        colour::yellow_ln!("{}", none_message);
    }

    Ok(None)
}

fn add_to_table(session: &KernelSession, table: &mut Table, cnt: &mut usize) {
    *cnt += 1;
    let (username, cid, endpoint, is_personal, runtime) = get_data_from_sess(session);
    table.add_row(prettytable::row![c => username, cid, endpoint, is_personal, runtime]);
}

fn get_data_from_sess(session: &KernelSession) -> (&String, u64, String, bool, u64) {
    (&session.username, session.cid, session.socket_addr.to_string(), session.is_personal, session.elapsed_time_seconds())
}

async fn handle_ffi(ctx: &ConsoleContext, list_type: ListType) -> KernelResponse {
    let mut ret = ActiveSessions::default();
    ctx.list_all_sessions(|sess| {
        match list_type {
            ListType::All => {
                ret.insert(get_data_from_sess(sess))
            }

            ListType::Personal => {
                if sess.is_personal {
                    ret.insert(get_data_from_sess(sess))
                }
            }

            ListType::Impersonal => {
                if !sess.is_personal {
                    ret.insert(get_data_from_sess(sess))
                }
            }
        }
    }).await;

    KernelResponse::DomainSpecificResponse(DomainResponse::GetActiveSessions(ret))
}