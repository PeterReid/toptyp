


use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::path::PathBuf;
use std::fs::File;
use std::io::Read;
use std::time::SystemTime;
use std::error::Error;

use std::time::UNIX_EPOCH;
use url::Url;
use std::ffi::CStr;
use totp_lite::totp_custom;
use std::fs::{OpenOptions, remove_file, rename};
use std::io::Write;

static ACCOUNTS: Lazy<Mutex<Vec<Account>>> = Lazy::new(|| {
    Mutex::new(vec![])
});

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    fn as_u32(self) -> u32 {
        match self {
            Algorithm::Sha1 => 1,
            Algorithm::Sha256 => 256,
            Algorithm::Sha512 => 512,
        }
    }
    
    fn url_encoding(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Account {
    name: String,
    secret: Vec<u8>,
    algorithm: Algorithm,
    period: u64,
    digits: u32,
}

#[derive(Debug)]
enum TotpError {
    MalformedUrl = 1,
    UnsupportedCodeType = 2,
    DuplicateQueryParameters = 3,
    MalformedSecret = 4,
    UnsupportedDigitCount = 5,
    UnsupportedPeriod = 6,
    UnsupportedAlgorithm = 7,
    MissingSecret = 8,
    MalformedDigits = 9,
    MalformedPeriod = 10,
    MalformedName = 11,
    FileWriteError = 12,
    AccountNotFound = 13,
}

impl ::std::fmt::Display for TotpError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> Result<(), ::std::fmt::Error> {
        write!(f, "TotpError({:?})", self)
    }
}
impl Error for TotpError {
    
}


impl Account {
    fn from_c_params(name_str: &CStr, code_str: &CStr, algorithm: u32, digits: u32, period: u32) -> Result<Account, TotpError> {
        Ok(Account {
            name: name_str.to_str().map_err(|_| TotpError::MalformedName)?.to_string(),
            secret: base32::decode(base32::Alphabet::RFC4648{padding: false}, code_str.to_str().map_err(|_| TotpError::MalformedSecret)?).ok_or(TotpError::MalformedSecret)?,
            algorithm: match algorithm {
                1 => Algorithm::Sha1,
                256 => Algorithm::Sha256,
                512 => Algorithm::Sha512,
                _ => {
                    return Err(TotpError::UnsupportedAlgorithm)
                }
            },
            period: match period {
                15 | 30 | 60 => { period as u64 },
                _ => {
                    return Err(TotpError::UnsupportedPeriod)
                }
            },
            digits : match digits {
                6 | 8 | 10 => { digits },
                _ => {
                    return Err(TotpError::UnsupportedDigitCount)
                }
            }
        })
    }

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
                    issuer = Some(percent_encoding::percent_decode_str(&val).decode_utf8_lossy().to_string());
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
        let name = issuer.or(path_issuer).unwrap_or_else(|| without_slash.to_string());
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
    
    fn to_url(&self) -> String {
        format!("otpauth://totp/?secret={}&issuer={}&algorithm={}&digits={}&period={}", 
            base32::encode(base32::Alphabet::RFC4648{padding: false}, &self.secret), 
            percent_encoding::percent_encode(self.name.as_bytes(), percent_encoding::NON_ALPHANUMERIC), 
            self.algorithm.url_encoding(),
            self.digits,
            self.period)
    }
}

fn write_to_buffer(dest: &mut [u8], value: &str) -> Result<(), Box<dyn Error>> {
    let value_bytes = value.as_bytes();
    
    if value_bytes.len()+1 > dest.len() {
        Err(format!("Not enough space to write into a buffer"))?;
    }
    
    dest[..value_bytes.len()].copy_from_slice(value_bytes);
    dest[value_bytes.len()] = 0;
    Ok( () )
}

fn empty_string_into_buffer(dest: &mut [u8]) {
    if dest.len() > 0 {
        dest[0] = 0;
    }
}

#[no_mangle]
pub extern "C" fn load_accounts() -> u32 {
    result_to_error_code(load_accounts_inner())
}

fn get_save_file() -> Result<PathBuf, Box<dyn Error>> {
    let mut dir = dirs::config_dir().unwrap_or(PathBuf::from("."));
    dir.push("totp.txt");
    Ok(dir)
}
fn get_save_temp_file() -> Result<PathBuf, Box<dyn Error>> {
    let mut dir = dirs::config_dir().unwrap_or(PathBuf::from("."));
    dir.push("totp.txt.temp");
    Ok(dir)
}

fn load_accounts_inner() -> Result<(), Box<dyn Error>> {
    let dir = get_save_file()?;
    println!("{:?}", dir);
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


#[no_mangle]
pub extern "C" fn accounts_len() -> u32 {
    ACCOUNTS.lock().ok().and_then(|accounts| accounts.len().try_into().ok()).unwrap_or(0)
}

fn result_to_error_code<E: std::fmt::Debug>(r: Result<(), E>) -> u32 {
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

fn get_account_by_index(accounts: &mut Vec<Account>, index: u32) -> Result<&mut Account, Box<dyn Error>> {
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
    let account = get_account_by_index(&mut accounts, index)?;
    
    write_to_buffer(dest, account.name.as_str())?;
    Ok( () )
}

#[no_mangle]
pub extern "C" fn get_code(index: u32, dest: *mut u8, dest_len: u32, millis_per_code: *mut u32, millis_into_code: *mut u32) -> u32 {
    result_to_error_code(get_code_inner(index, dest, dest_len, millis_per_code, millis_into_code))
}

fn get_code_inner(index: u32, dest: *mut u8, dest_len: u32, millis_per_code: *mut u32, millis_into_code: *mut u32) -> Result<(), Box<dyn Error>> {
    let dest = unsafe { ::std::slice::from_raw_parts_mut(dest, dest_len.try_into()?) };
    empty_string_into_buffer(dest);
    
    let mut accounts = ACCOUNTS.lock()?;
    let account = get_account_by_index(&mut accounts, index)?;
    
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let seconds: u64 = since_epoch.as_secs();
    let code = match account.algorithm {
        Algorithm::Sha1 => totp_custom::<totp_lite::Sha1>(account.period, account.digits, &account.secret, seconds),
        Algorithm::Sha256 => totp_custom::<totp_lite::Sha256>(account.period, account.digits, &account.secret, seconds),
        Algorithm::Sha512 => totp_custom::<totp_lite::Sha512>(account.period, account.digits, &account.secret, seconds),
    };
    
    write_to_buffer(dest, code.as_str())?;
    
    unsafe {
        *millis_per_code = (account.period * 1000) as u32;
        *millis_into_code = ((seconds % account.period) as u32) * 1000 + since_epoch.subsec_millis();
    }
    
    Ok( () )
}

#[no_mangle]
pub extern "C" fn add_account(name: *const u8, code: *const u8, algorithm: u32, digits: u32, period: u32) -> u32 {
    result_to_error_code(add_account_inner(name, code, algorithm, digits, period))
}

fn add_account_inner(name: *const u8, code: *const u8, algorithm: u32, digits: u32, period: u32) -> Result<(), Box<dyn Error>> {
    let name_str = unsafe { CStr::from_ptr(name as *const i8) };
    let code_str = unsafe { CStr::from_ptr(code as *const i8) };
    
    let account = Account::from_c_params(name_str, code_str, algorithm, digits, period)?;
    atomic_file_modification(&|mut data: Vec<String>| {
        data.push(account.to_url());
        Ok( data )
    })?;

    load_accounts_inner()?;
    
    Ok( () )
}


#[no_mangle]
pub extern "C" fn delete_account(index: u32) -> u32 {
    result_to_error_code(delete_account_inner(index))
}

fn find_account_index(account: &Account, expected_at_line: u32, lines: &[String]) -> Option<usize> {
    let mut best_line_idx = None;
    let mut best_line_distance = None;
    for (line_idx, line) in lines.iter().enumerate() {
        let account_on_line = match Account::from_url(&line) {
            Ok(account_on_line) => account_on_line,
            Err(_) => { continue; }
        };
        if account_on_line == *account {
            let distance = ((line_idx as i32) - (expected_at_line as i32)).abs();
            if match best_line_distance { None => true, Some(best_line_distance) => distance < best_line_distance } {
                best_line_idx = Some(line_idx);
                best_line_distance = Some(distance);
            }
        }
    }
    best_line_idx
}

fn delete_account_inner(index: u32) -> Result<(), Box<dyn Error>> {
    // We know exactly what account we want to delete in the in-memory ACCOUNTS, but there
    // is no guarantee that the file has not changed from under us.
    {
        let mut accounts = ACCOUNTS.lock()?;
        let target_account = get_account_by_index(&mut accounts, index)?;
        
        atomic_file_modification(&|mut data: Vec<String>| {
            if let Some(best_line_idx) = find_account_index(target_account, index, &data) {
                data.remove(best_line_idx);
                Ok(data)
            } else {
                Err(TotpError::AccountNotFound)
            }
        })?;
    }
    
    load_accounts_inner()?;
    
    Ok( () )
}

fn atomic_file_modification(modify_data: &dyn Fn(Vec<String>) -> Result<Vec<String>, TotpError>) -> Result<(), Box<dyn Error>> {
    let temp_file_path = get_save_temp_file()?;
    let data_file_path = get_save_file()?;
    
    if temp_file_path.exists() {
        remove_file(&temp_file_path)?; // If this doesn't get removed, we have another instance actively working on the file. That is very strange, so report the errot to user.
    }
    
    let mut temp_file = OpenOptions::new().write(true).create_new(true).open(&temp_file_path)?;
    let mut old_data_bytes = Vec::new();
    if data_file_path.exists() {
        File::open(&data_file_path)?.read_to_end(&mut old_data_bytes)?;
    }
    let old_data = String::from_utf8(old_data_bytes)?;
    let old_data_lines: Vec<String> = old_data.lines().map(|line| line.trim()).filter(|line| line.len()>0).map(|s| s.to_string()).collect();
    let new_data_lines = modify_data(old_data_lines)?;
    let new_data = new_data_lines.join("\r\n");
    temp_file.write_all(new_data.as_bytes())?;
    drop(temp_file);
    rename(temp_file_path, data_file_path)?;
    
    Ok( () )
}


#[no_mangle]
pub extern "C" fn get_account(index: u32, name: *mut u8, name_len: u32, code: *mut u8, code_len: u32, algorithm: *mut u32, digits: *mut u32, period: *mut u32) -> u32 {
    result_to_error_code(get_account_inner(index, name, name_len, code, code_len, algorithm, digits, period))
}

fn get_account_inner(index: u32, name: *mut u8, name_len: u32, code: *mut u8, code_len: u32, algorithm: *mut u32, digits: *mut u32, period: *mut u32) -> Result<(), Box<dyn Error>> {
    let name = unsafe { ::std::slice::from_raw_parts_mut(name, name_len.try_into()?) };
    let code = unsafe { ::std::slice::from_raw_parts_mut(code, code_len.try_into()?) };
    
    let mut accounts = ACCOUNTS.lock()?;
    let account = get_account_by_index(&mut accounts, index)?;
    
    write_to_buffer(name, account.name.as_str())?;
    write_to_buffer(code, &base32::encode(base32::Alphabet::RFC4648{padding: false}, &account.secret))?;
    
    unsafe {
        *algorithm = account.algorithm.as_u32();
        *digits = account.digits as u32;
        *period = account.period as u32;
    }
    
    Ok( () )
}

#[no_mangle]
pub extern "C" fn edit_account(index: u32, name: *const u8, code: *const u8, algorithm: u32, digits: u32, period: u32) -> u32 {
    result_to_error_code(edit_account_inner(index, name, code, algorithm, digits, period))
}

fn edit_account_inner(index: u32, name: *const u8, code: *const u8, algorithm: u32, digits: u32, period: u32) -> Result<(), Box<dyn Error>> {
    {
        let name_str = unsafe { CStr::from_ptr(name as *const i8) };
        let code_str = unsafe { CStr::from_ptr(code as *const i8) };

        let mut accounts = ACCOUNTS.lock()?;
        let target_currently_is = get_account_by_index(&mut accounts, index)?;
        
        let target_will_be = Account::from_c_params(name_str, code_str, algorithm, digits, period)?;

        atomic_file_modification(&|mut data: Vec<String>| {
            let modify_index = if let Some(modify_index) = find_account_index(target_currently_is, index, &data) {
                modify_index
            } else {
                return Err(TotpError::AccountNotFound);
            };
            
            let url_parts = Url::parse(&data[modify_index]).map_err(|_| TotpError::MalformedUrl)?;
            let mut url_modified = url_parts.clone();
            
            {
                let mut modified_query = url_modified.query_pairs_mut();
                modified_query.clear();
                for (key, val) in url_parts.query_pairs() {
                    match key.as_ref() {
                        "secret" => modified_query.append_pair("secret", &base32::encode(base32::Alphabet::RFC4648{padding: false}, &target_will_be.secret)),
                        "algorithm" => modified_query.append_pair("algorithm", target_will_be.algorithm.url_encoding()),
                        "issuer" => modified_query.append_pair("issuer", &percent_encoding::percent_encode(target_will_be.name.as_bytes(), percent_encoding::NON_ALPHANUMERIC).to_string()),
                        "period" => modified_query.append_pair("period", &target_will_be.period.to_string()),
                        "digits" => modified_query.append_pair("digits", &target_will_be.digits.to_string()),
                        _ => {
                            modified_query.append_pair(&key, &val)
                        }
                    };
                };
            }
            
            data[modify_index] = url_modified.to_string();
            
            Ok(data)
        })?;
    }
    
    load_accounts_inner()?;
    
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
/*
#[test]
fn get_account_name_test() {
    load_accounts_inner().unwrap();
    let mut buf = [0u8; 100];
    get_account_name(0, buf.as_mut_ptr(), 100);
    println!("{:?}", buf);
    panic!();
}
*/

#[test]
fn add_account_test() {
    
    assert_eq!(add_account(b"Ninja\0".as_ptr(), b"BSAPF2T4OEVIAB2D".as_ptr(), 1, 6, 30), 0);
    panic!();
}

#[test]
fn load_account_test() {
    
    load_accounts();
    
    let mut name_buf = [0u8; 255];
    let mut code_buf = [0u8; 255];
    let mut algorithm: u32 = 0;
    let mut period: u32 = 0;
    let mut digits: u32 = 0;
    assert_eq!(get_account(2, name_buf.as_mut_ptr(), 255, code_buf.as_mut_ptr(), 255, &mut algorithm, &mut digits, &mut period), 0);
    println!("{:?} {:?} {} {} {}", unsafe { CStr::from_ptr(name_buf.as_ptr() as *const u8 as *const i8) }, unsafe { CStr::from_ptr(code_buf.as_ptr() as *const u8 as *const i8) }, algorithm, period, digits);
    
    println!("{:?}", &ACCOUNTS.lock().unwrap());
    
    assert_eq!(delete_account(2), 0);
    //assert_eq!(edit_account(2, name_buf.as_ptr(), code_buf.as_ptr(), 256, 15, 10), 0);
    
    panic!();
    
    
}