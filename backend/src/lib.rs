


use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::path::{Path, PathBuf};
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
use std::ops::DerefMut;
use std::collections::HashSet;

use arboard::Clipboard;

use argon2::Argon2;
use argon2::password_hash::rand_core::RngCore;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305
};

static ACCOUNTS: Lazy<Mutex<Vec<Account>>> = Lazy::new(|| {
    Mutex::new(vec![])
});
static SEARCH_QUERY: Lazy<Mutex<String>> = Lazy::new(|| { Mutex::new(String::new()) });
static SEARCH_RESULTS: Lazy<Mutex<Vec<usize>>> = Lazy::new(|| { Mutex::new(vec![]) });
static SCAN_RESULTS: Lazy<Mutex<Vec<Account>>> = Lazy::new(|| {
    Mutex::new(vec![])
});
static IMPORT_CONTENTS: Lazy<Mutex<String>> = Lazy::new(|| { Mutex::new(String::new()) });

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

#[derive(Debug, Copy, Clone)]
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
    ImageTooLarge = 14,
    IndexOutOfRange = 15,
    FileReadError = 16,
    UnsupportedPassword = 17,
    InternalError = 18,
    PasswordNeededForImport = 19,
    EditInProgress = 20,
    MalformedFileText = 21,
    DecryptFailed = 22,
    UndersizedBuffer = 23,
    UnsupportedBufferSize = 24,
    MalformedSearchQuery = 25,
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

fn write_to_buffer(dest: &mut [u8], value: &str) -> Result<(), TotpError> {
    let value_bytes = value.as_bytes();
    
    if value_bytes.len()+1 > dest.len() {
        return Err(TotpError::UndersizedBuffer);
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

fn get_save_file() -> PathBuf {
    let mut dir = dirs::config_dir().unwrap_or(PathBuf::from("."));
    dir.push("totp.txt");
    dir
}
fn get_save_temp_file() -> PathBuf {
    let mut dir = dirs::config_dir().unwrap_or(PathBuf::from("."));
    dir.push("totp.txt.temp");
    dir
}

fn text_to_accounts(text: &str) -> Result<Vec<Account>, TotpError> {
    let mut accounts = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line == "" {
            continue;
        }
        
        let account = Account::from_url(line)?;
        accounts.push(account);
    }
    Ok(accounts)
}

fn load_accounts_inner() -> Result<(), TotpError> {
    // TODO: Also try temp path
    let data = file_to_string(&get_save_file())?;
    {
        let mut accounts = ACCOUNTS.lock().map_err(|_| TotpError::InternalError)?;
        *accounts.deref_mut() = text_to_accounts(&data)?;
    }
    update_search_results()
}


#[no_mangle]
pub extern "C" fn accounts_len() -> u32 {
    SEARCH_RESULTS.lock().ok().and_then(|accounts| accounts.len().try_into().ok()).unwrap_or(0)
}

fn result_to_error_code(r: Result<(), TotpError>) -> u32 {
    match r {
        Ok( () ) => 0,
        Err( e ) => e as u32
    }
}

#[no_mangle]
pub extern "C" fn get_account_name(index: u32, dest: *mut u8, dest_len: u32) -> u32 {
    result_to_error_code(get_account_name_inner(index, dest, dest_len))
}

fn get_account_by_index(accounts: &mut Vec<Account>, index: u32) -> Result<&mut Account, TotpError> {
    let index: usize = index.try_into().map_err(|_| TotpError::IndexOutOfRange)?;
    let search_results = SEARCH_RESULTS.lock().map_err(|_| TotpError::InternalError)?;
    
    if index >= search_results.len() {
        Err(TotpError::IndexOutOfRange)?;
    }
    let accounts_idx = search_results[index];
    if accounts_idx >= accounts.len() {
        return Err(TotpError::InternalError); // Search results incoherent
    }
    Ok(&mut accounts[accounts_idx])
}

fn get_account_name_inner(index: u32, dest: *mut u8, dest_len: u32) -> Result<(), TotpError> {
    let dest = unsafe { ::std::slice::from_raw_parts_mut(dest, dest_len.try_into().map_err(|_| TotpError::UnsupportedBufferSize)?) };
    empty_string_into_buffer(dest);
    
    let mut accounts = ACCOUNTS.lock().map_err(|_| TotpError::InternalError)?;
    let account = get_account_by_index(&mut accounts, index)?;
    
    write_to_buffer(dest, account.name.as_str())?;
    Ok( () )
}

#[no_mangle]
pub extern "C" fn get_code(index: u32, dest: *mut u8, dest_len: u32, millis_per_code: *mut u32, millis_into_code: *mut u32) -> u32 {
    result_to_error_code(get_code_inner(index, dest, dest_len, millis_per_code, millis_into_code))
}

fn get_code_inner(index: u32, dest: *mut u8, dest_len: u32, millis_per_code: *mut u32, millis_into_code: *mut u32) -> Result<(), TotpError> {
    let dest = unsafe { ::std::slice::from_raw_parts_mut(dest, dest_len.try_into().map_err(|_| TotpError::UnsupportedBufferSize)?) };
    empty_string_into_buffer(dest);
    
    let mut accounts = ACCOUNTS.lock().map_err(|_| TotpError::InternalError)?;
    let account = get_account_by_index(&mut accounts, index)?;
    
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| TotpError::InternalError)?;
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

fn add_account_inner(name: *const u8, code: *const u8, algorithm: u32, digits: u32, period: u32) -> Result<(), TotpError> {
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

fn delete_account_inner(index: u32) -> Result<(), TotpError> {
    // We know exactly what account we want to delete in the in-memory ACCOUNTS, but there
    // is no guarantee that the file has not changed from under us.
    {
        let mut accounts = ACCOUNTS.lock().map_err(|_| TotpError::InternalError)?;
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

#[no_mangle]
pub extern "C" fn set_search_query(query: *const u8) -> u32 {
    result_to_error_code(set_search_query_inner(query))
}

fn update_search_results() -> Result<(), TotpError> {
    let accounts = ACCOUNTS.lock().map_err(|_| TotpError::InternalError)?;
    let mut search_results = SEARCH_RESULTS.lock().map_err(|_| TotpError::InternalError)?;
    let search_query = SEARCH_QUERY.lock().map_err(|_| TotpError::InternalError)?;
    let search_query_str: String = search_query.clone().to_lowercase();
    
    *search_results = (*accounts).iter().enumerate().filter_map(|(idx, account)| {
        if account.name.to_lowercase().find(&search_query_str).is_some() {
            Some(idx)
        } else {
            None
        }
    }).collect();
    
    Ok( () )
}

fn set_search_query_inner(query: *const u8) -> Result<(), TotpError> {
    let query_str = unsafe { CStr::from_ptr(query as *const i8) };
    {
        let mut search_query = SEARCH_QUERY.lock().map_err(|_| TotpError::InternalError)?;
        
        *search_query = query_str.to_str().map_err(|_| TotpError::MalformedSearchQuery)?.to_string();
    }
    update_search_results()
}

fn file_to_string(path: &Path) -> Result<String, TotpError> {
    // TODO: Enforce a reasonable size limit, so we don't hang in the case of a many-GB file
    let mut data_bytes = Vec::new();
    if path.exists() {
        File::open(&path).and_then(|mut f| f.read_to_end(&mut data_bytes)).map_err(|_| TotpError::FileReadError)?;
    }
    String::from_utf8(data_bytes).map_err(|_| TotpError::MalformedFileText)
}

fn atomic_file_modification(modify_data: &dyn Fn(Vec<String>) -> Result<Vec<String>, TotpError>) -> Result<(), TotpError> {
    let temp_file_path = get_save_temp_file();
    let data_file_path = get_save_file();
    
    if temp_file_path.exists() {
        if data_file_path.exists() {
            // A previous atomic file modification must have be interrupted.
            rename(&data_file_path, &temp_file_path).map_err(|_| TotpError::EditInProgress)?;
        } else {
            remove_file(&temp_file_path).map_err(|_| TotpError::EditInProgress)?; // If this doesn't get removed, we have another instance actively working on the file. That is very strange, so report the errot to user.
        }
    }
    
    let mut temp_file = OpenOptions::new().write(true).create_new(true).open(&temp_file_path).map_err(|_| TotpError::FileWriteError)?;
    let old_data = file_to_string(&data_file_path)?;
    let old_data_lines: Vec<String> = old_data.lines().map(|line| line.trim()).filter(|line| line.len()>0).map(|s| s.to_string()).collect();
    let new_data_lines = modify_data(old_data_lines)?;
    let new_data = new_data_lines.join("\r\n");
    temp_file.write_all(new_data.as_bytes()).map_err(|_| TotpError::FileWriteError)?;
    drop(temp_file);
    rename(temp_file_path, data_file_path).map_err(|_| TotpError::FileWriteError)?;
    
    Ok( () )
}


#[no_mangle]
pub extern "C" fn get_account(index: u32, from_scan_results: u32, name: *mut u8, name_len: u32, code: *mut u8, code_len: u32, algorithm: *mut u32, digits: *mut u32, period: *mut u32) -> u32 {
    result_to_error_code(get_account_inner(index, from_scan_results, name, name_len, code, code_len, algorithm, digits, period))
}

fn get_account_inner(index: u32, from_scan_results: u32, name: *mut u8, name_len: u32, code: *mut u8, code_len: u32, algorithm: *mut u32, digits: *mut u32, period: *mut u32) -> Result<(), TotpError> {
    let name = unsafe { ::std::slice::from_raw_parts_mut(name, name_len.try_into().map_err(|_| TotpError::UnsupportedBufferSize)?) };
    let code = unsafe { ::std::slice::from_raw_parts_mut(code, code_len.try_into().map_err(|_| TotpError::UnsupportedBufferSize)?) };
    
    let mut accounts = (if from_scan_results==0 { ACCOUNTS.lock() } else { SCAN_RESULTS.lock() }).map_err(|_| TotpError::InternalError)?;
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
pub extern "C" fn scan(brightness: *const u8, width: u32, height: u32) -> u32 {
    result_to_error_code(scan_inner(brightness, width, height))
}




fn scan_inner(brightness: *const u8, width: u32, height: u32) -> Result<(), TotpError> {
    let width: usize = width.try_into().map_err(|_| TotpError::ImageTooLarge)?;
    let height: usize = height.try_into().map_err(|_| TotpError::ImageTooLarge)?;
    let byte_count = width.checked_mul(height).ok_or(TotpError::ImageTooLarge)?;
    let brightness: &[u8] = unsafe { ::std::slice::from_raw_parts(brightness, byte_count) };

    let mut scan_results = Vec::new();
    
    // create a decoder
    let mut decoder = quircs::Quirc::default();

    // identify all qr codes
    let codes = decoder.identify(width, height, brightness);

    for code in codes {
        if let Ok(extracted_code) = code {
            if let Ok(decoded) = extracted_code.decode() {
                if let Ok(account) = Account::from_url(std::str::from_utf8(&decoded.payload).unwrap()) {
                    scan_results.push(account);
                }
            }
        }
    }
    
    let mut scan_results_global = SCAN_RESULTS.lock().map_err(|_| TotpError::InternalError)?;
    *scan_results_global = scan_results;
    
    Ok( () )
}

#[no_mangle]
pub extern "C" fn scan_result_count() -> u32 {
    SCAN_RESULTS.lock().map_err(|_| ()).and_then(|scan_results| {
        scan_results.len().try_into().map_err(|_| ())
    }).unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn edit_account(index: u32, name: *const u8, code: *const u8, algorithm: u32, digits: u32, period: u32) -> u32 {
    result_to_error_code(edit_account_inner(index, name, code, algorithm, digits, period))
}

fn edit_account_inner(index: u32, name: *const u8, code: *const u8, algorithm: u32, digits: u32, period: u32) -> Result<(), TotpError> {
    {
        let name_str = unsafe { CStr::from_ptr(name as *const i8) };
        let code_str = unsafe { CStr::from_ptr(code as *const i8) };

        let mut accounts = ACCOUNTS.lock().map_err(|_| TotpError::InternalError)?;
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
            
            let mut secret = Some(base32::encode(base32::Alphabet::RFC4648{padding: false}, &target_will_be.secret));
            let mut algorithm = Some(target_will_be.algorithm.url_encoding());
            let mut issuer = Some(percent_encoding::percent_encode(target_will_be.name.as_bytes(), percent_encoding::NON_ALPHANUMERIC).to_string());
            let mut period = Some(target_will_be.period.to_string());
            let mut digits = Some(target_will_be.digits.to_string());
            
            {
                let mut modified_query = url_modified.query_pairs_mut();
                modified_query.clear();
                for (key, val) in url_parts.query_pairs() {
                    match key.as_ref() {
                        "secret" => if let Some(secret) = secret.take() { modified_query.append_pair("secret", &secret); },
                        "algorithm" => if let Some(algorithm) = algorithm.take() { modified_query.append_pair("algorithm", algorithm); },
                        "issuer" => if let Some(issuer) = issuer.take() { modified_query.append_pair("issuer", &issuer); },
                        "period" => if let Some(period) = period.take() { modified_query.append_pair("period", &period); },
                        "digits" => if let Some(digits) = digits.take() { modified_query.append_pair("digits", &digits); },
                        _ => {
                            modified_query.append_pair(&key, &val);
                        }
                    };
                };
                
                if let Some(secret) = secret {
                    modified_query.append_pair("secret", &secret);
                }
                if let Some(algorithm) = algorithm {
                    modified_query.append_pair("algorithm", &algorithm);
                }
                if let Some(issuer) = issuer {
                    modified_query.append_pair("issuer", &issuer);
                }
                if let Some(period) = period {
                    modified_query.append_pair("period", &period);
                }
                if let Some(digits) = digits {
                    modified_query.append_pair("digits", &digits);
                }
            }
            
            
            data[modify_index] = url_modified.to_string();
            
            Ok(data)
        })?;
    }
    
    load_accounts_inner()?;
    
    Ok( () )
}

use std::ffi::OsString;

#[cfg(target_os = "windows")]
unsafe fn u16s_to_osstring(data: *const u16) -> OsString {
    use std::os::windows::ffi::OsStringExt;

    let mut len = 0usize;
    while *data.offset(len as isize) != 0 {
        len += 1;
    }
    let data_slice: &[u16] = unsafe { ::std::slice::from_raw_parts(data, len) };

    OsString::from_wide(data_slice)
}

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "C" fn export_to_file_on_windows(path: *const u16) -> u32 {
	let path = unsafe { u16s_to_osstring(path) };
    result_to_error_code(export_to_file(path))
}

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "C" fn export_to_encrypted_file_on_windows(path: *const u16, password: *const u8) -> u32 {
	let path = unsafe { u16s_to_osstring(path) };
    result_to_error_code(export_to_encrypted_file(path, password))
}

fn export_to_file(path: OsString) -> Result<(), TotpError> {
    let dir = get_save_file();
    let mut data = Vec::new();
    File::open(&dir).and_then(|mut f| f.read_to_end(&mut data)).map_err(|_| TotpError::FileReadError)?;
    File::create(path).and_then(|mut f| f.write_all(&data)).map_err(|_| TotpError::FileWriteError)?;
    Ok( () )
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], TotpError> {
    let mut output_key_material = [0u8; 32]; // Can be any desired size
    Argon2::default().hash_password_into(password.as_bytes(), salt, &mut output_key_material).map_err(|_| TotpError::UnsupportedPassword)?;
    Ok(output_key_material)
}

fn byte_encrypt(plaintext: &[u8], password: &str) -> Result<Vec<u8>, TotpError> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    
    let key = derive_key(password, &salt[..])?.into();
    let cipher = ChaCha20Poly1305::new(&key );
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let mut ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
    ciphertext.extend(salt);
    ciphertext.extend(nonce);
    Ok(ciphertext)
}

fn chunkify_text(mut text: &str) -> String {
    let mut result = String::new();
    let mut chunk_index = 0;
    while text.len() > 8 {
        let (chunk, remaining_text) = text.split_at(8);
        result.push_str(chunk);
        result.push(if chunk_index%8==7 { '\n' } else { ' ' });
        
        chunk_index += 1;
        text = remaining_text;
    }
    result.push_str(text);
    result
}

fn string_encrypt(plaintext: &str, password: &str) -> Result<String, TotpError> {
    let encrypted_data = byte_encrypt(plaintext.as_bytes(), password)?;
    let encrypted_text = base32::encode(base32::Alphabet::RFC4648{padding: false}, &encrypted_data);
    let encrypted_text_chunked = chunkify_text(&encrypted_text);
    Ok(encrypted_text_chunked)
}

fn encrypt_with_password(password: *const u8) -> Result<String, TotpError> {
    let password = unsafe { CStr::from_ptr(password as *const i8) };
    let plaintext = file_to_string(&get_save_file())?;
    let password = password.to_str().map_err(|_| TotpError::UnsupportedPassword)?;
    string_encrypt(&plaintext, password)
}

fn export_to_encrypted_file(path: OsString, password: *const u8) -> Result<(), TotpError> {
    let encrypted_text = encrypt_with_password(password)?;
    File::create(path).and_then(|mut f| f.write_all(encrypted_text.as_bytes())).map_err(|_| TotpError::FileWriteError)?;
    Ok( () )
}

#[no_mangle]
pub extern "C" fn export_to_clipboard() -> u32 {
    result_to_error_code(export_to_clipboard_inner())
}

fn export_to_clipboard_inner() -> Result<(), TotpError> {
    let mut clipboard = Clipboard::new().map_err(|_| TotpError::InternalError)?;
    let data = file_to_string(&get_save_file())?;
    clipboard.set_text(data).map_err(|_| TotpError::InternalError)?;
    Ok( () )
}

#[no_mangle]
pub extern "C" fn export_encrypted_to_clipboard(password: *const u8) -> u32 {
    result_to_error_code(export_encrypted_to_clipboard_inner(password))
}

fn export_encrypted_to_clipboard_inner(password: *const u8) -> Result<(), TotpError> {
    let mut clipboard = Clipboard::new().map_err(|_| TotpError::InternalError)?;
    let encrypted_text = encrypt_with_password(password)?;
    clipboard.set_text(encrypted_text).map_err(|_| TotpError::InternalError)?;
    Ok( () )
}

#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "C" fn import_on_windows(path: *const u16, password: *const u8) -> u32 {
    let path = unsafe { u16s_to_osstring(path) };
    result_to_error_code(import_inner(path, password))
}

#[no_mangle]
pub extern "C" fn import_from_clipboard(password: *const u8) -> u32 {
    result_to_error_code(import_from_clipboard_inner(password))
}

fn import_from_clipboard_inner(password: *const u8) -> Result<(), TotpError> {
    let mut clipboard = Clipboard::new().map_err(|_| TotpError::InternalError)?;
    let mut contents = IMPORT_CONTENTS.lock().map_err(|_| TotpError::InternalError)?;
    *contents = clipboard.get_text().map_err(|_| TotpError::InternalError)?;
    
    import_string(&contents, password)
}

#[no_mangle]
pub extern "C" fn import_retry(password: *const u8) -> u32 {
    result_to_error_code(import_retry_inner(password))
}

fn import_retry_inner(password: *const u8) -> Result<(), TotpError> {
    let contents = IMPORT_CONTENTS.lock().unwrap();
    import_string(&contents, password)
}

fn extract_ciphertext(data: &str) -> Option<Vec<u8>> {
    let mut base32_chars = String::new();
    let mut consecutive_base32_chars = 0;
    let mut ending = false;
    for c in data.chars() {
        if c.is_whitespace() {
            if consecutive_base32_chars != 0 && consecutive_base32_chars != 8 {
                // A group of characters that is not exactly 8 characters long had better be the end.
                ending = true;
            }
            consecutive_base32_chars = 0;
        } else if (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') {
            if ending {
                return None;
            }
            consecutive_base32_chars += 1;
            if consecutive_base32_chars > 8 {
                return None;
            }
            base32_chars.push(c);
        }
    }
    
    base32::decode(base32::Alphabet::RFC4648{padding: false}, &base32_chars)
}

fn import_plaintext(plaintext: &str) -> Result<(), TotpError> {
    let imported_accounts = text_to_accounts(plaintext)?;
    atomic_file_modification(&|mut data: Vec<String>| {
        let mut existings = HashSet::new();
        for existing in data.iter() {
            existings.insert(existing.clone());
        }
        
        for imported_account in imported_accounts.iter() {
            let imported_account_str = imported_account.to_url();
            if !existings.contains(&imported_account_str) {
                data.push(imported_account_str);
            }
        }
        
        Ok( data )
    })?;

    load_accounts_inner()?;
    
    Ok( () )
}

fn decrypt(ciphertext: &[u8], password: &str) -> Result<String, TotpError> {
    if ciphertext.len() < 12+16 {
        return Err(TotpError::DecryptFailed);
    }
    let (ciphertext_body, salt_and_nonce) = ciphertext.split_at(ciphertext.len() - (12+16));
    let (salt, nonce) = salt_and_nonce.split_at(16);
    
    let key = derive_key(password, salt)?.into();
    let cipher = ChaCha20Poly1305::new(&key);
    let plaintext = cipher.decrypt(nonce.into(), ciphertext_body).map_err(|_| TotpError::DecryptFailed)?;
    String::from_utf8(plaintext).map_err(|_| TotpError::MalformedFileText)
}

fn import_inner(path: OsString, password: *const u8) -> Result<(), TotpError> {
    let mut contents = IMPORT_CONTENTS.lock().map_err(|_| TotpError::InternalError)?;
    *contents = file_to_string(&PathBuf::from(path))?;
    import_string(&contents, password)
}
    
fn import_string(data: &str, password: *const u8) -> Result<(), TotpError> {
    let password = if password.is_null() { None } else { Some(unsafe { CStr::from_ptr(password as *const i8) }) };
    if let Some(ciphertext) = extract_ciphertext(&data) {
        match password {
            Some(password) => {
                let plaintext: String = decrypt(&ciphertext, password.to_str().map_err(|_| TotpError::UnsupportedPassword)?)?;
                import_plaintext(&plaintext)?;
            }
            None => { return Err(TotpError::PasswordNeededForImport); }
        }
    } else {
        import_plaintext(data)?;
    }
    
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
/*
#[test]
fn add_account_test() {
    
    assert_eq!(add_account(b"Ninja\0".as_ptr(), b"BSAPF3T4OEVIAB2D".as_ptr(), 1, 6, 30), 0);
    panic!();
}*/
/*
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
    
    //assert_eq!(delete_account(2), 0);
    //assert_eq!(edit_account(2, name_buf.as_ptr(), code_buf.as_ptr(), 256, 15, 10), 0);
    
    panic!();
    
    
}*/


#[test]
fn encryption_round_trip() {
    let plaintext = "arbitrary plaintext".to_string();
    let password = "the quick brown fox jumped over the lazy dog";
    let ciphertext = string_encrypt(&plaintext, password).unwrap();
    let ciphertext_bytes = extract_ciphertext(&ciphertext).unwrap();
    let plaintext_again = decrypt(&ciphertext_bytes, password).unwrap();
    assert_eq!(plaintext, plaintext_again);
    
    assert!(decrypt(&ciphertext_bytes, "wrong password").is_err());
}

#[test]
fn import_test() {
    match import_inner("C:\\Users\\Peter\\Documents\\encsecrets.txt".into(), std::ptr::null()) {
        Err(TotpError::PasswordNeededForImport) => {
            
        }
        _ => {
            assert!(false);
        }
    }
    
    match import_inner("C:\\Users\\Peter\\Documents\\encsecrets.txt".into(), b"testpassword\0".as_ptr()) {
        Ok( () ) => {
            
        }
        Err(e) => {
            panic!("failed import {}", e as u32);
        }
    }
    
}