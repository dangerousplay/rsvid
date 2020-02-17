use url::{Url, Host};
use url::ParseError as ParseUrlError;
use std::borrow::Cow;
use thiserror::Error;

const SCHEME: &str = "spiffe";

/// This represents a SPIFFE Identity (or SPIFFE ID), a URI comprising a “trust domain” and an associated path.
/// The trust domain stands as the authority component of the URI, and serves to identify the system in which
/// a given identity is issued.
///
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpiffeID {
    url: Url
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ParseError {
    #[error("Invalid SPIFFE ID URL: {0}")]
    InvalidUrl(#[from] ParseUrlError),

    #[error("Invalid SPIFFE ID: {0}")]
    InvalidSPIFFEID(Cow<'static, str>)
}

macro_rules! ensure_id {
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            return Err(ParseError::InvalidSPIFFEID(format!($fmt, $($arg)*).into()));
        }
    };
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return Err(ParseError::InvalidSPIFFEID(($msg).into()));
        }
    };
}

impl SpiffeID {
    pub fn new<'a>(spiffe_id: impl Into<Cow<'a, str>>) -> Result<Self, ParseError> {
        let url = Url::parse(spiffe_id.into().as_ref())
            .map_err(ParseError::InvalidUrl)?;

        ensure_id!(url.scheme().to_lowercase().as_str() == SCHEME, "Expected Scheme {}, found: `{}`", SCHEME, url.scheme());
        ensure_id!(url.has_host(), "Host is empty: `{}`", url);
        ensure_id!(url.fragment().is_none(), "Fragment is not allowed, found: `{}`", url.fragment().unwrap());
        ensure_id!(url.query().is_none(), "Query is not allowed, found: `{}`", url.query().unwrap());
        ensure_id!(url.port().is_none(), "Port is not allowed, found: `{}`", url.port().unwrap());
        ensure_id!(url.password().is_none(), "Password is not allowed, found: `{}`", url.password().unwrap());
        ensure_id!(url.username().is_empty(), "Username is not allowed, found: `{}`", url.username());

        Ok(Self {
            url
        })
    }

    fn is_workload(&self) -> bool {
        self.url.path_segments()
            .and_then(|mut p| p.next())
            .map(|p| !p.is_empty())
            .unwrap_or(true)
    }

    pub fn trust_domain(&self) -> &str {
        self.url.domain().expect("Bug on Host validation")
    }

    pub fn workload_id(&self) -> Option<String> {
        self.url.path_segments()
            .filter(|_| self.is_workload())
            .map(|v| v.collect::<Vec<_>>().join("/"))
    }

    pub fn inner_url(&self) -> &Url {
        &self.url
    }
}

impl ToString for SpiffeID {
    fn to_string(&self) -> String {
        self.url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_url() {
        let actual = SpiffeID::new("example.domain.com")
            .expect_err("Should return an error because url is invalid");

        match actual {
            ParseError::InvalidUrl(err) => {
                match err {
                    ParseUrlError::RelativeUrlWithoutBase => {},
                    _ => panic!("Not relative url without base error")
                }
            },
            _ => panic!("Not invalid url error")
        }
    }

    #[test]
    fn test_not_a_base() {
        SpiffeID::new("spiffa:example.domain.com")
            .expect_err("Should return an error because is not a base");
    }

    #[test]
    fn test_scheme_invalid() {
        SpiffeID::new("spiff://example.domain3.com")
            .expect_err("Should return an error because scheme is not spiffe");
    }

    #[test]
    fn test_non_root_path() {
        let actual = SpiffeID::new("spiffe://example.domain2.com/A").unwrap();

        assert_eq!(actual.workload_id().unwrap(), "A");
        assert_eq!(actual.is_workload(), true);
    }

    #[test]
    fn test_root_path() {
        let actual = SpiffeID::new("spiffe://example.domain2.com/").unwrap();

        assert!(actual.workload_id().is_none());
        assert_eq!(actual.is_workload(), false);

        let actual = SpiffeID::new("spiffe://example.domain2.com///aaa").unwrap();

        assert!(actual.workload_id().is_none());
        assert_eq!(actual.is_workload(), false);
    }

    #[test]
    fn test_to_string() {
        let url = "spiffe://example.domain3.com/amazon/workload";

        let actual = SpiffeID::new(url.to_string()).unwrap();

        assert_eq!(actual.to_string(), url);
    }

    #[test]
    fn test_port_rule() {
        SpiffeID::new("spiffe://example.domain2.com:8080/A")
            .expect_err("Should return an error because port is not allowed");
    }

    #[test]
    fn test_query_rule() {
        SpiffeID::new("spiffe://example.domain2.com/A?A=b")
            .expect_err("Should return an error because query is not allowed");
    }

    #[test]
    fn test_user_info_rule() {
        SpiffeID::new("spiffe://user:pass@example.domain2.com")
            .expect_err("Should return an error because user info is not allowed");
    }

    #[test]
    fn test_fragment_rule() {
        SpiffeID::new("spiffe://user:pass@example.domain2.com/#aaab")
            .expect_err("Should return an error because fragment is not allowed");
    }

}