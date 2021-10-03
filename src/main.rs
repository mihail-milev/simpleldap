use tokio::net::{TcpListener, TcpStream};
use futures::{SinkExt, StreamExt};
use std::str::FromStr;
use std::{net, process};
use std::convert::TryFrom;
use tokio_util::codec::{FramedRead, FramedWrite};
use ldap3_server::LdapCodec;
use ldap3_server::simple::{ServerOps, LdapResultCode, WhoamiRequest, LdapSearchScope,
                            DisconnectionNotice, SimpleBindRequest, LdapMsg, LdapFilter,
                            LdapPartialAttribute, SearchRequest, LdapSearchResultEntry};
use sqlite::{Connection, OpenFlags, Value};
use regex::Regex;
use crypto::sha2::Sha512;
use crypto::digest::Digest;

#[derive(Clone)]
struct Database {
    path: String,
}

struct UserDef {
    uid: String,
    dn: String,
    passhash: String,
    maysearch: i64,
    email: String,
    given_name: String,
    surname: String,
}

impl Database {
    pub fn new(dbpath: &str) -> Database {
        return Database{path: String::from(dbpath)};
    }

    fn extract_uid(&self, dn: &str) -> Result<String, String> {
        let re = match Regex::new(r"^uid=(\w+),.*?$") {
            Ok(r) => r,
            Err(e) => {
                return Err(format!("Unable to create regex: {}", e).to_string());
            }
        };
        for cap in re.captures_iter(dn) {
            let uid = match cap.get(1) {
                Some(u) => u.as_str(),
                None => continue,
            };
            return Ok(uid.to_string());
        };
        return Err(format!("UID not found in: {}", dn));
    }

    pub fn search_user(&self, search: &str, scope: LdapSearchScope) -> Result<Vec<UserDef>, String> {
        let conn = match self.open() {
            Ok(c) => c,
            Err(e) => {
                return Err(format!("{}", e));
            },
        };
        let filter = if scope == LdapSearchScope::Subtree {
            " like "
        } else {
            "="
        };
        let mut cursor = match conn.prepare(format!("select * from users where userbase{}?", filter)) {
            Ok(s) => s.into_cursor(),
            Err(e) => {
                return Err(format!("Unable to create prepare statement: {}", e));
            },
        };
        match cursor.bind(&[Value::String(search.to_string())]) {
            Ok(c) => c,
            Err(e) => {
                return Err(format!("Unable to fill prepared statement with data: {}", e));
            },
        };
        let mut res : Vec<UserDef> = vec![];
        while let Some(ln) = cursor.next().unwrap() {
            let uid = match self.extract_uid(ln[0].as_string().unwrap()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{}", e);
                    continue;
                }
            };
            res.push(UserDef {
                uid: uid,
                dn: ln[0].as_string().unwrap().to_string(),
                passhash: ln[1].as_string().unwrap().to_string(),
                maysearch: ln[2].as_integer().unwrap(),
                given_name: ln[3].as_string().unwrap().to_string(),
                surname: ln[4].as_string().unwrap().to_string(),
                email: ln[5].as_string().unwrap().to_string(),
            });
        }

        return Ok(res)
    }

    fn open(&self) -> Result<Connection, String> {
        let of = OpenFlags::new().set_read_only();
        match sqlite::Connection::open_with_flags(self.path.clone(), of) {
            Ok(c) => {
                return Ok(c);
            },
            Err(e) => {
                return Err(format!("Unable to open filepath: {}", e));
            },
        };
    }
}

struct LdapSession {
    dn: String,
    maysearch: bool,
}

impl LdapSession {
    fn check_dn_format(&self, dn: &str) -> Result<bool, String> {
        let re = match Regex::new(r"^(?:\w+=\w+,)*?(?:\w+=\w+)$") {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Unable to compile regular expression: {}", e);
                return Err("Internal Server Error".to_string());
            },
        };
        if !re.is_match(dn) {
            eprintln!("Non-conformant bind string: {}", dn);
            return Ok(false);
        }
        return Ok(true);
    }

    pub fn do_bind(&mut self, sbr: &SimpleBindRequest, db: Box<Database>) -> LdapMsg {
        println!("Performing bind:
    DN: {}", sbr.dn);
        match self.check_dn_format(sbr.dn.as_str()) {
            Ok(b) => {
                if !b {
                    return sbr.gen_error(LdapResultCode::InvalidAttributeSyntax, "Bind string non-conformant".to_string());
                }
            },
            Err(e) => {
                return sbr.gen_error(LdapResultCode::Other, e);
            }
        };
        let users = match db.search_user(sbr.dn.as_str(), LdapSearchScope::Base) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("{}", e);
                return sbr.gen_error(LdapResultCode::OperationsError, e);
            }
        };
        let mut hasher = Sha512::new();
        hasher.input_str(sbr.pw.as_str());
        let passhex = hasher.result_str();
        println!("    Bind pass hex: {}", passhex);
        for user in users {
            if user.passhash == passhex {
                self.dn = user.dn;
                if user.maysearch > 0 {
                    self.maysearch = true;
                }
                println!("    Bind success: {}", self.dn);
                return sbr.gen_success();
            }
        }
        println!("    Bind failed");
        return sbr.gen_invalid_cred();
    }

    fn recurse_filters(&self, fltr: &ldap3_server::LdapFilter) -> String {
        match fltr {
            LdapFilter::Equality(itm, uname) => {
                if itm == "uid" {
                    return uname.to_string();
                }
            },
            LdapFilter::And(fltrs) => {
                for fltr in fltrs {
                    let res = self.recurse_filters(fltr);
                    if res != "%" {
                        return res;
                    }
                }
            },
            LdapFilter::Or(fltrs) => {
                for fltr in fltrs {
                    let res = self.recurse_filters(fltr);
                    if res != "%" {
                        return res;
                    }
                }
            },
            _ => {},
        };
        return "%".to_string();
    }

    pub fn do_search(&mut self, lsr: &SearchRequest, db: Box<Database>) -> Vec<LdapMsg> {
        println!("Perform search:
    Filter: {:?}
    Scope: {:?}
    Attributes: {:?}
    Base: {}", lsr.filter, lsr.scope, lsr.attrs, lsr.base);
        match self.check_dn_format(lsr.base.as_str()) {
            Ok(b) => {
                if !b {
                    return vec![lsr.gen_error(LdapResultCode::InvalidAttributeSyntax, "Search string non-conformant".to_string())];
                }
            },
            Err(e) => {
                return vec![lsr.gen_error(LdapResultCode::Other, e)];
            }
        };
        let re = match Regex::new(r"^uid=\w+,(.*?)$") {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Unable to create regex: {}", e);
                return vec![lsr.gen_error(LdapResultCode::Other, "Internal Server Error".to_string())];
            }
        };
        let search : String;
        let perform_tuname_check : bool;
        if re.is_match(lsr.base.as_str()) {
            search = lsr.base.to_string();
            perform_tuname_check = false;
        } else {
            let tuname = self.recurse_filters(&lsr.filter);
            search = format!("uid={},{}", tuname, lsr.base);
            if tuname == "%" {
                perform_tuname_check = true;
            } else {
                perform_tuname_check = false;
            }
        }
        println!("    User search: {}", search);
        let users = match db.search_user(search.as_str(), lsr.scope.clone()) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("{}", e);
                return vec![lsr.gen_error(LdapResultCode::Other, "Internal Server Error".to_string())];
            }
        };
        let mut res : Vec<LdapMsg> = vec![];
        let tuname_check = match Regex::new(format!(r"uid=\w+,{}", lsr.base).as_str()) {
            Ok(r) => r,
            Err(e) =>{
                eprintln!("Unable to create tuname_check regex: {}", e);
                return vec![lsr.gen_error(LdapResultCode::Other, "Internal Server Error".to_string())];
            }
        };
        for user in users {
            if perform_tuname_check {
                if !tuname_check.is_match(user.dn.as_str()) {
                    continue;
                }
            }
            if !self.maysearch && self.dn != user.dn {
                continue;
            }
            println!("    User found: {}", user.dn);
            res.push(lsr.gen_result_entry(LdapSearchResultEntry {
                        dn: user.dn,
                        attributes: vec![
                            LdapPartialAttribute {
                                atype: "objectClass".to_string(),
                                vals: vec!["users".to_string()],
                            },
                            LdapPartialAttribute {
                                atype: "cn".to_string(),
                                vals: vec![format!("{} {}", user.given_name, user.surname)],
                            },
                            LdapPartialAttribute {
                                atype: "uid".to_string(),
                                vals: vec![user.uid],
                            },
                            LdapPartialAttribute {
                                atype: "givenName".to_string(),
                                vals: vec![user.given_name],
                            },
                            LdapPartialAttribute {
                                atype: "surname".to_string(),
                                vals: vec![user.surname],
                            },
                            LdapPartialAttribute {
                                atype: "email".to_string(),
                                vals: vec![user.email],
                            },
                        ],
                    }));
        }
        res.push(lsr.gen_success());
        return res;
    }

    pub fn do_whoami(&mut self, wr: &WhoamiRequest) -> LdapMsg {
        wr.gen_success(format!("dn: {}", self.dn).as_str())
    }
}

async fn handle_client(socket: TcpStream, _paddr: net::SocketAddr, db: Box<Database>) {
    // Configure the codec etc.
    let (r, w) = tokio::io::split(socket);
    let mut reqs = FramedRead::new(r, LdapCodec);
    let mut resp = FramedWrite::new(w, LdapCodec);

    let mut session = LdapSession {
        dn: "Anonymous".to_string(),
        maysearch: false,
    };

    while let Some(msg) = reqs.next().await {
        let server_op = match msg.map_err(|_e| ()).and_then(|msg| ServerOps::try_from(msg)) {
            Ok(v) => v,
            Err(_) => {
                let _err = resp
                    .send(DisconnectionNotice::gen(LdapResultCode::Other,
                        "Internal Server Error",
                    )).await;
                let _err = resp.flush().await;
                return;
            }
        };

        let result = match server_op {
            ServerOps::SimpleBind(sbr) => vec![session.do_bind(&sbr, db.clone())],
            ServerOps::Search(sr) => session.do_search(&sr, db.clone()),
            ServerOps::Unbind(_) => {
                // No need to notify on unbind (per rfc4511)
                return;
            }
            ServerOps::Whoami(wr) => vec![session.do_whoami(&wr)],
        };

        for rmsg in result.into_iter() {
            if let Err(_) = resp.send(rmsg).await {
                return;
            }
        }

        if let Err(_) = resp.flush().await {
            return;
        }
    }
    // Client disconnected
}

async fn acceptor(listener: Box<TcpListener>, db: Box<Database>) {
    loop {
        match listener.accept().await {
            Ok((socket, paddr)) => {
                tokio::spawn(handle_client(socket, paddr, db.clone()));
            }
            Err(e) => {
                eprintln!("Unable to accept client: {}", e);
            },
        };
    }
}

#[tokio::main]
async fn main() -> () {
    let addr = "0.0.0.0:12345";

    let db = Box::new(Database::new("database.sqlite"));

    let addr = match net::SocketAddr::from_str(addr) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Unable to build address: {}", e);
            process::exit(-1);
        },
    };
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Unable to bind to address: {}", e);
            process::exit(-1);
        },
    };
    let listener = Box::new(listener);

    // Initiate the acceptor task.
    tokio::spawn(acceptor(listener, db));

    println!("started ldap://{} ...", addr);
    match tokio::signal::ctrl_c().await {
        Ok(_) => {},
        Err(e) => {
            eprintln!("Problem capturing Ctrl+C: {}", e);
            process::exit(-1);
        },
    };
}