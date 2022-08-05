use crate::{GrantType, TokenType};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::convert::TryFrom;
use uriparse::URI;

pub trait AsStr {
    fn as_str(&self) -> &'static str;
}

fn check_vschars(str: &str) -> bool {
    str.chars().all(|c| ('\x20'..='\x7e').contains(&c))
}

fn check_nqchars(str: &str) -> bool {
    str.chars().all(|c| ('\x21'..='\x7e').contains(&c) && c != '\x22' && c != '\x5c')
}

fn check_nqschars(str: &str) -> bool {
    str.chars().all(|c|
        c == '\x09' ||
            ('\x20'..='\x7e').contains(&c) ||
            ('\u{0080}'..='\u{d7ff}').contains(&c) ||
            ('\u{e000}'..='\u{fffd}').contains(&c) ||
            ('\u{10000}'..='\u{10ffff}').contains(&c)
    )
}

fn check_scope_token(str: &str) -> bool {
    str.len() >= 1 && check_nqschars(str)
}

fn check_response_chars(str: &str) -> bool {
    str.chars().all(|c| c == '_' || c.is_ascii_digit() || c.is_ascii_alphanumeric())
}

fn check_name_chars(str: &str) -> bool {
    str.chars().all(|c| c == '-' || c == '.' || c == '_' || c.is_ascii_digit() || c.is_ascii_alphanumeric())
}

fn check_digit_chars(str: &str) -> bool {
    str.chars().all(|c| c.is_ascii_digit())
}

fn check_grant_name(str: &str) -> bool {
    str.len() >= 1 && check_name_chars(str)
}

pub fn check_no_duplicates(strs: &Vec<&str>) -> bool {
    let mut map: HashMap<&str, PhantomData<()>> = HashMap::with_capacity(strs.len());
    for s in strs {
        match map.insert(*s, PhantomData) {
            Some(v_) => return false,
            None => continue
        }
    }
    true
}

fn validate_vschars_min(str: &str, min: usize) -> Result<(), ()> {
    match str.len() >= min {
        true => match check_vschars(str) {
            true => Ok(()),
            false => Err(())
        },
        false => Err(())
    }
}

fn validate_digit_chars_min(str: &str, min: usize) -> Result<(), ()> {
    match str.len() >= min {
        true => match check_digit_chars(str) {
            true => Ok(()),
            false => Err(())
        },
        false => Err(())
    }
}

/// A.5.  "state" Syntax
pub fn validate_state(str: &str) -> Result<(), ()> {
    validate_vschars_min(str, 1)
}

/// A.1.  "client_id" Syntax
pub fn validate_client_id(str: &str) -> Result<(), ()> {
    validate_vschars_min(str, 0)
}

/// A.11.  "code" Syntax
pub fn validate_code(str: &str) -> Result<(), ()> {
    validate_vschars_min(str, 1)
}

/// A.12.  "access_token" Syntax
pub fn validate_access_token(str: &str) -> Result<(), ()> {
    validate_vschars_min(str, 1)
}

/// A.17.  "refresh_token" Syntax
pub fn validate_refresh_token(str: &str) -> Result<(), ()> {
    validate_vschars_min(str, 1)
}

/// A.4.  "scope" Syntax
pub fn validate_scope(scope: &str) -> Result<Vec<&str>, ()> {
    let scope_tokens = scope.split(' ').collect::<Vec<&str>>();
    match scope_tokens.iter().all(|st| check_scope_token(*st)) && check_no_duplicates(&scope_tokens) {
        true => Ok(scope_tokens),
        false => Err(())
    }
}

/// A.6.  "redirect_uri" Syntax
pub fn validate_uri(uri: &str) -> Result<URI, ()> {
    let uri = match uriparse::URI::try_from(uri) {
        Ok(u) => u,
        Err(_) => return Err(())
    };
    match !uri.has_fragment() {
        true => Ok(uri),
        false => Err(())
    }
}

/// A.3.  "response_type" Syntax
pub fn validate_response_type(response_type: &str) -> Result<Vec<&str>, ()> {
    let response_types = response_type.split(' ').collect::<Vec<&str>>();
    match response_types.iter().all(|st| check_response_chars(*st)) {
        true => Ok(response_types),
        false => Err(())
    }
}

/// A.10.  "grant_type" Syntax
pub fn validate_grant_type(grant_type: &str) -> Result<GrantType, ()> {
    match check_grant_name(grant_type) {
        true => Ok(GrantType::Name(grant_type)),
        false => match validate_uri(grant_type) {
            Ok(uri) => Ok(GrantType::Uri(uri)),
            Err(_) => Err(())
        }
    }
}

/// A.13.  "token_type" Syntax
pub fn validate_token_type(str: &str) -> Result<TokenType, ()> {
    match validate_grant_type(str) {
        Ok(t) => match t {
            GrantType::Name(n) => TokenType::try_from(n),
            //Unsupported for now
            GrantType::Uri(_) => Err(())
        },
        Err(_) => Err(())
    }
}