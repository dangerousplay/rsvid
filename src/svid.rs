use thiserror::Error;
use crate::url::SpiffeID;
use openssl::x509::X509;
use openssl::x509::X509Req;
use std::borrow::Cow;
use openssl::error::ErrorStack;

#[derive(Error, Debug)]
pub enum ParseError<'a> {
    #[error("Invalid SVID certificate: `{0}`")]
    InvalidSVID(Cow<'a, str>),

    #[error("Invalid X509 certificate: `{0}`")]
    InvalidX509(#[from] ErrorStack),
}

pub enum CertificateType {
    Leaf,
    Signing
}

/// This represents a SPIFFE Verifiable Identity Document (SVID).
///
/// A SVID can be either:
///  * A leaf certificate is an SVID which serves to identify a caller or resource and are suitable
///    for use in authentication processes. A leaf certificate is the only type which may serve to identify
///    a resource or caller.
///  * A signing certificate. A signing certificate MAY be used to issue further signing certificates in the same
///    or different trust domains. Signing certificates MUST NOT be used for authentication purposes.
///    They serve as validation material only, and may be chained together in typical X.509 fashion
///
pub struct SVID {
    cert_type: CertificateType,
    inner: X509,
    spiffe_id: SpiffeID
}

impl SVID {

    pub fn from_der(der: &[u8]) -> Result<Self, ParseError<'static>> {
        let certificate = X509::from_der(der)
            .map_err(ParseError::InvalidX509)?;

        Self::from_certificate(certificate)
    }

    pub fn from_pem(pem: &[u8]) -> Result<Self, ParseError<'static>> {
        let certificate = X509::from_pem(pem)
            .map_err(ParseError::InvalidX509)?;

        Self::from_certificate(certificate)
    }

    pub fn from_certificate(cert: X509) -> Result<Self, ParseError<'static>> {
        unimplemented!()
    }

    ///The corresponding SPIFFE ID as a URI type
    pub fn spiffe_id(&self) -> &SpiffeID {
        &self.spiffe_id
    }

}

fn validate_svid(cert: &X509) -> Option<ParseError<'static>> {
    let a = cert

    unimplemented!()
}

fn validate_as_leaf(cert: &X509) -> Option<ParseError<'static>> {
    unimplemented!()
}

fn validate_spiffe_id(cert: &X509) -> Result<SpiffeID, ParseError<'static>> {

    //Necessary because of lifetime
    let sans = cert.subject_alt_names()
        .ok_or_else(|| ParseError::InvalidSVID("Doesn't has SAN".into()))?;

    let mut uri_sans = sans.iter()
        .filter_map(|v| v.uri());

    let spiffe_id: SpiffeID = uri_sans
        .next()
        .map(|uri| SpiffeID::new(uri))
        .ok_or_else(|| ParseError::InvalidSVID("Doesn't has URI SAN".into()))?
        .map_err(|e| ParseError::InvalidSVID(e.to_string().into()))?;

    let remaind: Vec<_> = uri_sans.collect();

    if !remaind.is_empty() {
        return Err(ParseError::InvalidSVID(format!("More than one SAN URI Type found: {:?}", remaind).into()))
    }

    Ok(spiffe_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_spiffe_id() {
        let pem = "-----BEGIN CERTIFICATE-----
MIIDsDCCApigAwIBAgIBATANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJBVTET
MBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQ
dHkgTHRkMB4XDTE4MDExNTExMDcwM1oXDTI4MDExMzExMDcwM1owfDELMAkGA1UE
BhMCVVMxCzAJBgNVBAgMAk5ZMREwDwYDVQQHDAhOZXcgWW9yazEVMBMGA1UECgwM
RXhhbXBsZSwgTExDMTYwNAYDVQQDDC1FeGFtcGxlIENvbXBhbnkvZW1haWxBZGRy
ZXNzPXRlc3RAZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCo9CWMRLMXo1CF/iORh9B4NhtJF/8tR9PlG95sNvyWuQQ/8jfev+8zErpl
xfLkt0pJqcoiZG8g9NU0kU6o5T+/1QgZclCAoZaS0Jqxmoo2Yk/1Qsj16pnMBc10
uSDk6V9aJSX1vKwONVNSwiHA1MhX+i7Wf7/K0niq+k7hOkhleFkWgZtUq41gXh1V
fOugka7UktYnk9mrBbAMjmaloZNn2pMMAQxVg4ThiLm3zvuWqvXASWzUZc7IAd1G
bN4AtDuhs252eqE9E4iTHk7F14wAS1JWqv666hReGHrmZJGx0xQTM9vPD1HN5t2U
3KTfhO/mTlAUWVyg9tCtOzboKgs1AgMBAAGjdDByMAkGA1UdEwQCMAAwCwYDVR0P
BAQDAgWgMFgGA1UdEQRRME+CC2V4YW1wbGUuY29thwR/AAABhxAAAAAAAAAAAAAA
AAAAAAABgRB0ZXN0QGV4YW1wbGUuY29thhZodHRwOi8vd3d3LmV4YW1wbGUuY29t
MA0GCSqGSIb3DQEBCwUAA4IBAQAx14G99z/MnSbs8h5jSos+dgLvhc2IQB/3CChE
hPyELc7iyw1iteRs7bS1m2NZx6gv6TZ6VydDrK1dnWSatQ7sskXTO+zfC6qjMwXl
IV+u7T8EREwciniIA82d8GWs60BGyBL3zp2iUOr5ULG4+c/S6OLdlyJv+fDKv+Xo
fKv1UGDi5rcvUBikeNkpEPTN9UsE9/A8XJfDyq+4RKuDW19EtzOOeVx4xpHOMnAy
VVAQVMKJzhoXtLF4k2j409na+f6FIcZSBet+plmzfB+WZNIgUUi/7MQIXOFQRkj4
zH3SnsPm/IYpJzlH2vHhlqIBdaSoTWpGVWPq7D+H8OS3mmXF
-----END CERTIFICATE-----";

        let cert = openssl::x509::X509::from_pem(pem.as_bytes()).unwrap();

        let aaf = validate_svid(&cert);

        let res = validate_spiffe_id(&cert);

        res.unwrap_err();
    }

}
