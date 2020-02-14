use url::Url;
use url::ParseError as ParseUrlError;
use std::borrow::Cow;
use thiserror::Error;

const SCHEME: &str = "spiffe";

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ParseError<'a> {
    #[error("Invalid URL: `{0}`")]
    InvalidUrl(#[from] ParseUrlError),

    #[error("Invalid scheme, expected `{}` found: `{0}`", SCHEME)]
    InvalidSchema(Cow<'a, str>)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpiffeID {
    url: Url
}

impl SpiffeID {
    pub fn new<'a>(spiffe_id: impl Into<Cow<'a, str>>) -> Result<Self, ParseError<'static>> {
        let url = Url::parse(spiffe_id.into().as_ref())
            .map_err(ParseError::InvalidUrl)?;

        if url.scheme() != SCHEME {
            return Err(ParseError::InvalidSchema(url.scheme().to_owned().into()))
        }

        Ok(Self {
            url
        })
    }

    pub fn is_root_path(&self) -> bool {
        self.url.path_segments()
            .and_then(|mut p| p.next())
            .map(|p| p.is_empty())
            .unwrap_or(true)
    }

    pub fn path(&self) -> &str {
        self.url.path()
    }

    pub fn url(&self) -> &Url {
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
            .expect_err("Should return an error");

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
        let actual = SpiffeID::new("spiffa:example.domain.com")
            .expect_err("Should return an error");

        assert_eq!(actual, ParseError::InvalidSchema("spiffa".into()));
    }

    #[test]
    fn test_schema_invalid() {
        let actual = SpiffeID::new("spiff://example.domain3.com").expect_err("Should return an error");

        assert_eq!(actual, ParseError::InvalidSchema("spiff".into()));
    }

    #[test]
    fn test_non_root_path() {
        let actual = SpiffeID::new("spiffe://example.domain2.com/A").unwrap();

        assert_eq!(actual.path(), "/A");
        assert_eq!(actual.is_root_path(), false);
    }

    #[test]
    fn test_root_path() {
        let actual = SpiffeID::new("spiffe://example.domain2.com/").unwrap();

        assert_eq!(actual.path(), "/");
        assert_eq!(actual.is_root_path(), true);
    }

    #[test]
    fn test_to_string() {
        let url = "spiffe://example.domain3.com/amazon/workload";

        let actual = SpiffeID::new("spiffe://example.domain2.com/A").unwrap();

        assert_eq!(actual.to_string(), url);
    }


}