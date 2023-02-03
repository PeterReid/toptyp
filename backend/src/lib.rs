


use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::path::PathBuf;
use std::fs::File;
use std::io::Read;
use std::time::SystemTime;
use std::error::Error;

use std::time::UNIX_EPOCH;
use url::Url;
use totp_lite::totp_custom;

static ACCOUNTS: Lazy<Mutex<Vec<Account>>> = Lazy::new(|| {
    Mutex::new(vec![])
});

#[derive(Debug, Eq, PartialEq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

struct Account {
    name: String,
    secret: Vec<u8>,
    algorithm: Algorithm,
    period: u64,
    digits: u32,
}

#[derive(Debug)]
enum TotpError {
    MalformedUrl,
    UnsupportedCodeType,
    DuplicateQueryParameters,
    MalformedSecret,
    UnsupportedDigitCount,
    UnsupportedPeriod,
    UnsupportedAlgorithm,
    MissingSecret,
    MalformedDigits,
    MalformedPeriod,
}

impl ::std::fmt::Display for TotpError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> Result<(), ::std::fmt::Error> {
        write!(f, "TotpError({:?})", self)
    }
}
impl Error for TotpError {
    
}


impl Account {
    fn from_url(url: &str) -> Result<Account, TotpError> {
        let url_parts = Url::parse(url).map_err(|_| TotpError::MalformedUrl)?;
        
        if url_parts.scheme() != "otpauth" {
            return Err(TotpError::MalformedUrl);
        }
        if url_parts.host_str() != Some("totp") {
            return Err(TotpError::UnsupportedCodeType);
        }
        
        let path = percent_encoding::percent_decode_str(url_parts.path()).decode_utf8_lossy();
        let without_slash = if path.starts_with('/') { path.split_at(1).1 } else { path.as_ref() };
        let path_issuer = without_slash.find(':').map(|colon| without_slash.split_at(colon).0.to_string());
        
        
        let mut algorithm = None;
        let mut period = None;
        let mut digits = None;
        let mut secret = None;
        let mut issuer = None;
        for (key, val) in url_parts.query_pairs() {
            match key.as_ref() {
                "secret" => {
                    if secret.is_some() { return Err(TotpError::DuplicateQueryParameters); }
                    secret = Some(base32::decode(base32::Alphabet::RFC4648{padding: false}, val.as_ref()).ok_or(TotpError::MalformedSecret)?);
                },
                "algorithm" => {
                    algorithm = Some(match val.as_ref() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => {
                            return Err(TotpError::UnsupportedAlgorithm);
                        }
                    })
                }
                "issuer" => {
                    issuer = Some(val.into_owned());
                }
                "period" => {
                    period = Some(val.as_ref().parse().map_err(|_| TotpError::MalformedPeriod)?)
                }
                "digits" => {
                    digits = Some(val.as_ref().parse().map_err(|_| TotpError::MalformedDigits)?)
                }
                _ => {
                }
            }
        }
        
        let algorithm = algorithm.unwrap_or(Algorithm::Sha1);
        let digits = digits.unwrap_or(6);
        let period = period.unwrap_or(30);
        let name = issuer.or(path_issuer).unwrap_or_else(|| "Untitled".to_string());
        let secret = secret.ok_or(TotpError::MissingSecret)?;
        
        if digits != 6 && digits != 8 && digits != 10 {
            return Err(TotpError::UnsupportedDigitCount);
        }
        if period != 15 && period != 30 && period != 60 {
            return Err(TotpError::UnsupportedPeriod);
        }
        
        Ok(Account{
           name: name,
           secret: secret,
           algorithm: algorithm,
           period: period,
           digits: digits,
        })
    }
}

fn write_to_buffer(dest: &mut [u8], value: &str) -> Result<(), Box<dyn Error>> {
    let value_bytes = value.as_bytes();
    
    if value_bytes.len()+1 > dest.len() {
        Err(format!("Not enough space to write into a buffer"))?;
    }
    
    dest.copy_from_slice(value_bytes);
    dest[value_bytes.len()] = 0;
    Ok( () )
}

fn empty_string_into_buffer(dest: &mut [u8]) {
    if dest.len() > 0 {
        dest[0] = 0;
    }
}

pub extern "C" fn load_accounts() -> u32 {
    result_to_error_code(load_accounts_inner())
}

fn load_accounts_inner() -> Result<(), Box<dyn Error>> {
    let mut dir = dirs::config_dir().unwrap_or(PathBuf::from("."));
    dir.push("totp.txt");
    
    let mut data = Vec::new();
    File::open(&dir)?.read_to_end(&mut data)?;
    
    let mut accounts = ACCOUNTS.lock()?;
    accounts.clear();
    
    let data = String::from_utf8(data)?;
    for line in data.lines() {
        let line = line.trim();
        if line == "" {
            continue;
        }
        
        let account = Account::from_url(line)?;
        (&mut accounts).push(account);
    }
    
    Ok( () )
}

fn result_to_error_code<E>(r: Result<(), E>) -> u32 {
    if r.is_ok() {
        0
    } else {
        1
    }
}

#[no_mangle]
pub extern "C" fn get_account_name(index: u32, dest: *mut u8, dest_len: u32) -> u32 {
    result_to_error_code(get_account_name_inner(index, dest, dest_len))
}

fn get_account(accounts: &mut Vec<Account>, index: u32) -> Result<&mut Account, Box<dyn Error>> {
    let index: usize = index.try_into()?;
    if index >= accounts.len() {
        Err(format!("Account index out of range (index {} with length {})", index, accounts.len()))?;
    }
    Ok(&mut accounts[index])
}

fn get_account_name_inner(index: u32, dest: *mut u8, dest_len: u32) -> Result<(), Box<dyn Error>> {
    let dest = unsafe { ::std::slice::from_raw_parts_mut(dest, dest_len.try_into()?) };
    empty_string_into_buffer(dest);
    
    let mut accounts = ACCOUNTS.lock()?;
    let account = get_account(&mut accounts, index)?;
    
    write_to_buffer(dest, account.name.as_str())?;
    Ok( () )
}

#[no_mangle]
pub extern "C" fn get_code(index: u32, dest: *mut u8, dest_len: u32) -> u32 {
    result_to_error_code(get_code_inner(index, dest, dest_len))
}

fn get_code_inner(index: u32, dest: *mut u8, dest_len: u32) -> Result<(), Box<dyn Error>> {
    let dest = unsafe { ::std::slice::from_raw_parts_mut(dest, dest_len.try_into()?) };
    empty_string_into_buffer(dest);
    
    let mut accounts = ACCOUNTS.lock()?;
    let account = get_account(&mut accounts, index)?;
    
    let seconds: u64 = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let code = match account.algorithm {
        Algorithm::Sha1 => totp_custom::<totp_lite::Sha1>(account.period, account.digits, &account.secret, seconds),
        Algorithm::Sha256 => totp_custom::<totp_lite::Sha256>(account.period, account.digits, &account.secret, seconds),
        Algorithm::Sha512 => totp_custom::<totp_lite::Sha512>(account.period, account.digits, &account.secret, seconds),
    };
    
    write_to_buffer(dest, code.as_str())?;
    
    Ok( () )
}

#[test]
fn otpauth_example() {
    let account = Account::from_url("otpauth://totp/ACME%20CoFromPath:john.doe@email.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=8&period=15").unwrap();
    assert_eq!(account.algorithm, Algorithm::Sha1);
    assert_eq!(account.name, "ACME Co");
    assert_eq!(account.digits, 8);
    assert_eq!(account.period, 15);
    assert_eq!(account.secret, vec![ b'H', b'e', b'l', b'l', b'o', b'!', 0xDE, 0xAD, 0xBE, 0xEF ]);
}


#[test]
fn otpauth_no_issuer_example() {
    let account = Account::from_url("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&algorithm=SHA1&digits=6&period=30").unwrap();
    assert_eq!(account.algorithm, Algorithm::Sha1);
    assert_eq!(account.name, "ACME Co");
}
