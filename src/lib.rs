
pub mod url;
pub mod svid;


#[cfg(test)]
mod tests {
    
    
    
    
    
    
    use rcgen::{Certificate, CertificateParams, IsCa, KeyPair};
    use rand::{thread_rng, RngCore};
    use rcgen::BasicConstraints::Unconstrained;
    use std::borrow::Cow;

    fn generate_random_ca() -> Certificate {
        let serial = thread_rng().next_u64();

        let subject = format!("CA {}", serial);

        let mut params = CertificateParams::new(vec![subject]);

        params.is_ca = IsCa::Ca(Unconstrained);
        params.serial_number = Some(serial);

        Certificate::from_params(params).expect("Failed to generate cert")
    }

    fn generate_random_ca_pool() -> impl std::iter::Iterator<Item = Certificate> {
        std::iter::repeat_with(|| generate_random_ca())
    }

    fn create_svid<'a>(root_ca: &Certificate, _spiffe_id: impl Into<Cow<'a, str>>) -> Certificate {
        let serial = thread_rng().next_u64();

        let subject = format!("CA {}", serial);

        let mut params = CertificateParams::new(vec![subject]);

        params.serial_number = Some(serial);
//        params.subject_alt_names.push(SanType::Rfc822Name())

        let der = Certificate::from_params(params)
            .expect("Failed to generate cert")
            .serialize_der_with_signer(&root_ca)
            .expect("Failed to Sign");

        let key_pair = KeyPair::from_pem(&root_ca.get_key_pair().serialize_pem()).unwrap();

        let params = CertificateParams::from_ca_cert_der(&der, key_pair).unwrap();

        Certificate::from_params(params).unwrap()
    }

    #[test]
    fn it_works() {
        let cert = generate_random_ca();

        let _certs: Vec<_> = generate_random_ca_pool().take(10).collect();

        let fc = create_svid(&cert, "URL");

        panic!("{}", fc.serialize_pem().unwrap());

        assert_eq!(2 + 2, 4);
    }
}
