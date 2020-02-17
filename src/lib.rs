pub mod url;
pub mod svid;

#[cfg(test)]
mod tests {
    use rand::{thread_rng, RngCore};
    use std::borrow::Cow;
    use openssl::pkey::Private;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509, X509NameBuilder, X509ReqBuilder, X509Ref, X509Req, X509VerifyResult};
    use openssl::nid::Nid;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName, SubjectKeyIdentifier, KeyUsage, AuthorityKeyIdentifier};
    use crate::url::SpiffeID;
    use openssl::error::ErrorStack;
    use openssl::hash::MessageDigest;
    use openssl::asn1::Asn1Time;
    use openssl::pkey::PKeyRef;


    fn pkey() -> PKey<Private> {
        let rsa = Rsa::generate(2048).unwrap();
        PKey::from_rsa(rsa).unwrap()
    }

    // Make a CA certificate and private key
    fn mk_ca_cert(trust_domain: Option<&str>) -> Result<(X509, PKey<Private>), ErrorStack> {
        let privkey = pkey();

        let mut x509_name = X509NameBuilder::new()?;
        x509_name.append_entry_by_text("C", "US")?;
        x509_name.append_entry_by_text("ST", "TX")?;
        x509_name.append_entry_by_text("O", "Some CA organization")?;
        x509_name.append_entry_by_text("CN", "ca test")?;
        let x509_name = x509_name.build();

        let mut cert_builder = X509::builder()?;
        cert_builder.set_version(2)?;
        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        cert_builder.set_serial_number(&serial_number)?;
        cert_builder.set_subject_name(&x509_name)?;
        cert_builder.set_issuer_name(&x509_name)?;
        cert_builder.set_pubkey(&privkey)?;
        let not_before = Asn1Time::days_from_now(0)?;
        cert_builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(365)?;
        cert_builder.set_not_after(&not_after)?;

        cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        cert_builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;

        let subject_key_identifier =
            SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
        cert_builder.append_extension(subject_key_identifier)?;

        if let Some(uri) = trust_domain.and_then( |t| SpiffeID::new(t).ok()) {
            let spiffe_id = SubjectAlternativeName::new().uri(uri.to_string().as_str())
                .build(&cert_builder.x509v3_context(None, None))?;

            cert_builder.append_extension(spiffe_id)?;
        }

        cert_builder.sign(&privkey, MessageDigest::sha256())?;
        let cert = cert_builder.build();

        Ok((cert, privkey))
    }

    /// Make a X509 request with the given private key
    fn mk_request(privkey: &PKey<Private>) -> Result<X509Req, ErrorStack> {
        let public_key = PKey::public_key_from_pem(&privkey.public_key_to_pem()?)?;

        let mut req_builder = X509ReqBuilder::new()?;
        req_builder.set_pubkey(&public_key)?;

        let mut x509_name = X509NameBuilder::new()?;
        x509_name.append_entry_by_text("C", "US")?;
        x509_name.append_entry_by_text("ST", "TX")?;
        x509_name.append_entry_by_text("O", "Some organization")?;
        x509_name.append_entry_by_text("CN", "www.example.com")?;
        let x509_name = x509_name.build();
        req_builder.set_subject_name(&x509_name)?;

        req_builder.sign(&privkey, MessageDigest::sha256())?;
        let req = req_builder.build();
        Ok(req)
    }

    /// Make a certificate and private key signed by the given CA cert and private key
    fn mk_ca_signed_cert(
        ca_cert: &X509Ref,
        ca_privkey: &PKeyRef<Private>,
        workload_id: SpiffeID
    ) -> Result<(X509, PKey<Private>), ErrorStack> {
        let rsa = Rsa::generate(2048)?;
        let privkey = PKey::from_rsa(rsa)?;

        let req = mk_request(&privkey)?;

        let mut cert_builder = X509::builder()?;
        cert_builder.set_version(2)?;
        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        cert_builder.set_serial_number(&serial_number)?;
        cert_builder.set_subject_name(req.subject_name())?;
        cert_builder.set_issuer_name(ca_cert.subject_name())?;
        cert_builder.set_pubkey(&privkey)?;
        let not_before = Asn1Time::days_from_now(0)?;
        cert_builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(365)?;
        cert_builder.set_not_after(&not_after)?;

        cert_builder.append_extension(BasicConstraints::new().build()?)?;

        cert_builder.append_extension(
            KeyUsage::new()
                .critical()
                .non_repudiation()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )?;

        let subject_key_identifier =
            SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
        cert_builder.append_extension(subject_key_identifier)?;

        let auth_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
        cert_builder.append_extension(auth_key_identifier)?;

        let subject_alt_name = SubjectAlternativeName::new()
            .dns("*.example.com")
            .dns("hello.com")
            .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
        cert_builder.append_extension(subject_alt_name)?;

        let spiffe_id = SubjectAlternativeName::new()
            .uri(workload_id.to_string().as_str())
            .build(&cert_builder.x509v3_context(None, None))?;

        cert_builder.append_extension(spiffe_id)?;

        cert_builder.sign(&ca_privkey, MessageDigest::sha256())?;
        let cert = cert_builder.build();

        Ok((cert, privkey))
    }

    #[test]
    fn it_works() {
        let trust = Some("spiffe://domain.com");
        let spiffe_id = SpiffeID::new("spiffe://domain.com/AWS/AA").unwrap();

        let ca = mk_ca_cert(trust).unwrap();
        let ca2 = mk_ca_cert(None).unwrap();

        let req = mk_request(&ca.1).unwrap();
        let svid = mk_ca_signed_cert(&ca.0, &ca.1, spiffe_id).unwrap();

        let a = ca.0.issued(&svid.0);

        match a {
            X509VerifyResult::OK => println!("Certificate verified!"),
            ver_err => println!("Failed to verify certificate: {}", ver_err),
        };

        match ca2.0.issued(&svid.0) {
            X509VerifyResult::OK => println!("Certificate verified!"),
            ver_err => println!("Failed to verify certificate: {}", ver_err),
        }

        let b = 12;
    }
}
