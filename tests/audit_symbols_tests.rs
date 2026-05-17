mod common;

use std::path::Path;
use std::time::SystemTime;

use security::{
    Authorization, AuthorizationOptions, Certificate, Cms, CmsCertificateChainMode, CmsDecoder,
    CmsDigestAlgorithm, CmsEncoder, CmsSignedAttributes, Code, CodeSigningFlags, Identity, Policy,
    PrivateKey, Requirement, StaticCode, Task, Trust, TrustOptions,
};
use serde_json::{json, Value};

fn reference<T>(_value: T) {}

#[test]
fn authorization_new_api_symbols_compile() -> security::Result<()> {
    let authorization = Authorization::new()?;
    let _ = authorization.copy_info(None)?;

    reference(|value: &Authorization, rights: &[&str]| {
        value.copy_rights(rights, AuthorizationOptions::empty())
    });
    reference(|value: &Authorization, rights: &[&str]| {
        value.copy_rights_async(rights, AuthorizationOptions::empty())
    });
    Ok(())
}

#[test]
fn certificate_new_api_symbols_compile() -> security::Result<()> {
    let certificate = Certificate::from_der(&common::fixture("test-cert.der"))?;
    assert!(Certificate::type_id() > 0);
    let _ = certificate.values(&[])?;
    assert!(!certificate.long_description()?.is_empty());
    assert!(!certificate.short_description()?.is_empty());

    reference(|value: &Certificate| value.add_to_keychain());
    reference(|name: &str, key_usage: &[&str]| Certificate::preferred(name, key_usage));
    reference(
        |value: Option<&Certificate>, name: &str, key_usage: &[&str]| {
            Certificate::set_preferred(value, name, key_usage)
        },
    );
    Ok(())
}

#[test]
fn identity_new_api_symbols_compile() -> security::Result<()> {
    let identity =
        Identity::import_pkcs12_first(&common::fixture("test-identity.p12"), "password")?;
    assert!(Identity::type_id() > 0);
    let _ = identity.actual_domain()?;

    reference(|certificate: &Certificate, private_key: &PrivateKey| {
        Identity::from_certificate_and_private_key(certificate, private_key)
    });
    reference(|certificate: &Certificate| Identity::with_certificate(certificate));
    reference(
        |name: &str, key_usage: &[&str], valid_issuers: &[Vec<u8>]| {
            Identity::preferred(name, key_usage, valid_issuers)
        },
    );
    reference(
        |identity: Option<&Identity>, name: &str, key_usage: &[&str]| {
            Identity::set_preferred(identity, name, key_usage)
        },
    );
    reference(|domain: &str| Identity::copy_system_identity(domain));
    reference(|domain: &str, value: Option<&Identity>| {
        Identity::set_system_identity(domain, value)
    });
    Ok(())
}

#[test]
fn cms_new_api_symbols_compile() -> security::Result<()> {
    assert!(CmsDecoder::type_id() > 0);
    assert!(CmsEncoder::type_id() > 0);
    let _ = Cms::encoder()?;
    let _ = Cms::decoder()?;
    let _ = Cms::decode_all_certificates(&Cms::encode_supporting_certificates(&[
        Certificate::from_der(&common::fixture("test-cert.der"))?,
    ])?)?;

    reference(|decoder: &mut CmsDecoder, data: &[u8]| decoder.update_message(data));
    reference(|decoder: &mut CmsDecoder| decoder.finalize_message());
    reference(|decoder: &mut CmsDecoder, data: &[u8]| decoder.set_detached_content(data));
    reference(|decoder: &CmsDecoder| decoder.detached_content());
    reference(|decoder: &CmsDecoder| decoder.num_signers());
    reference(
        |decoder: &CmsDecoder, signer_index: usize, policy: Option<&Policy>, evaluate: bool| {
            decoder.signer_status(signer_index, policy, evaluate)
        },
    );
    reference(|decoder: &CmsDecoder, signer_index: usize| {
        decoder.signer_email_address(signer_index)
    });
    reference(|decoder: &CmsDecoder, signer_index: usize| decoder.signer_certificate(signer_index));
    reference(|decoder: &CmsDecoder| decoder.is_content_encrypted());
    reference(|decoder: &CmsDecoder| decoder.encapsulated_content_type());
    reference(|decoder: &CmsDecoder| decoder.content());
    reference(|decoder: &CmsDecoder, signer_index: usize| {
        decoder.signer_signing_time(signer_index)
    });
    reference(|decoder: &CmsDecoder, signer_index: usize| decoder.signer_timestamp(signer_index));
    reference(
        |decoder: &CmsDecoder, policy: Option<&Policy>, signer_index: usize| {
            decoder.signer_timestamp_with_policy(policy, signer_index)
        },
    );
    reference(|decoder: &CmsDecoder, signer_index: usize| {
        decoder.signer_timestamp_certificates(signer_index)
    });
    reference(|decoder: &CmsDecoder| decoder.all_certificates());

    reference(|encoder: &mut CmsEncoder, algorithm: CmsDigestAlgorithm| {
        encoder.set_signer_algorithm(algorithm)
    });
    reference(|encoder: &mut CmsEncoder, signers: &[Identity]| encoder.add_signers(signers));
    reference(|encoder: &CmsEncoder| encoder.signers());
    reference(|encoder: &mut CmsEncoder, recipients: &[Certificate]| {
        encoder.add_recipients(recipients)
    });
    reference(|encoder: &CmsEncoder| encoder.recipients());
    reference(|encoder: &mut CmsEncoder, detached: bool| {
        encoder.set_has_detached_content(detached)
    });
    reference(|encoder: &CmsEncoder| encoder.has_detached_content());
    reference(|encoder: &mut CmsEncoder, oid: &str| encoder.set_encapsulated_content_type_oid(oid));
    reference(|encoder: &CmsEncoder| encoder.encapsulated_content_type());
    reference(|encoder: &mut CmsEncoder, certs: &[Certificate]| {
        encoder.add_supporting_certificates(certs)
    });
    reference(|encoder: &CmsEncoder| encoder.supporting_certificates());
    reference(|encoder: &mut CmsEncoder, attrs: CmsSignedAttributes| {
        encoder.add_signed_attributes(attrs)
    });
    reference(|encoder: &mut CmsEncoder, mode: CmsCertificateChainMode| {
        encoder.set_certificate_chain_mode(mode)
    });
    reference(|encoder: &CmsEncoder| encoder.certificate_chain_mode());
    reference(|encoder: &mut CmsEncoder, data: &[u8]| encoder.update_content(data));
    reference(|encoder: &CmsEncoder| encoder.encoded_content());
    reference(|encoder: &CmsEncoder, signer_index: usize| encoder.signer_timestamp(signer_index));
    reference(
        |encoder: &CmsEncoder, policy: Option<&Policy>, signer_index: usize| {
            encoder.signer_timestamp_with_policy(policy, signer_index)
        },
    );

    reference(
        |signers: &[Identity],
         recipients: &[Certificate],
         oid: Option<&str>,
         detached: bool,
         attrs: CmsSignedAttributes,
         content: &[u8]| {
            Cms::encode_content(signers, recipients, oid, detached, attrs, content)
        },
    );
    Ok(())
}

#[test]
fn code_new_api_symbols_compile() -> security::Result<()> {
    let code = Code::current()?;
    let static_code = code.static_code()?;
    let task = Task::current()?;
    assert!(Code::type_id() > 0);
    assert!(Requirement::type_id() > 0);
    assert!(StaticCode::type_id() > 0);
    assert!(Task::type_id() > 0);

    let requirement = Requirement::from_string("anchor apple")?;
    let requirement_data = requirement.data()?;
    let requirement_text = requirement.string()?;
    assert!(!requirement_text.is_empty());
    let _ = Requirement::from_data(&requirement_data)?;
    let _ = Requirement::from_string_with_errors("anchor apple")?;
    let _ = StaticCode::from_path(static_code.path()?)?;
    let _ = Task::current_with_audit_token()?;
    let _ = task.entitlements(&["com.apple.security.app-sandbox"])?;

    reference(|value: &Code| value.host());
    reference(
        |host: Option<&Code>, attributes: Option<&Value>, flags: CodeSigningFlags| {
            Code::guest_with_attributes(host, attributes, flags)
        },
    );
    reference(|path: &Path, attributes: &Value| {
        StaticCode::from_path_with_attributes(path, attributes)
    });
    reference(
        |value: &StaticCode, flags: CodeSigningFlags, requirement: Option<&Requirement>| {
            value.check_validity_with_errors(flags, requirement)
        },
    );
    reference(
        |value: &StaticCode, flags: CodeSigningFlags, requirement: Option<&Requirement>| {
            value.check_static_validity(flags, requirement)
        },
    );
    reference(
        |value: &StaticCode, flags: CodeSigningFlags, requirement: Option<&Requirement>| {
            value.check_static_validity_with_errors(flags, requirement)
        },
    );
    reference(
        |value: &StaticCode, relative_path: &str, data: &[u8], flags: CodeSigningFlags| {
            value.validate_file_resource(relative_path, data, flags)
        },
    );
    reference(|value: &StaticCode, flags: CodeSigningFlags| value.map_memory(flags));
    Ok(())
}

#[test]
fn trust_new_api_symbols_compile() {
    reference(Trust::type_id as fn() -> usize);
    reference(|value: &Trust| value.policies());
    reference(|value: &Trust| value.custom_anchor_certificates());
    reference(|value: &Trust| value.network_fetch_allowed());
    reference(|value: &mut Trust, verify_date: SystemTime| value.set_verify_date(verify_date));
    reference(|value: &Trust| value.verify_time());
    reference(|value: &Trust| value.evaluate_async());
    reference(|value: &Trust| value.trust_result_type());
    reference(|value: &Trust| value.key());
    reference(|value: &Trust| value.certificate_count());
    reference(|value: &Trust| value.exceptions());
    reference(|value: &mut Trust, exceptions: Option<&[u8]>| value.set_exceptions(exceptions));
    reference(|value: &mut Trust, responses: &[Vec<u8>]| value.set_ocsp_responses(responses));
    reference(|value: &mut Trust, timestamps: &[Vec<u8>]| {
        value.set_signed_certificate_timestamps(timestamps)
    });
    reference(|value: &mut Trust, options: TrustOptions| value.set_options(options));
    reference(Trust::system_anchor_certificates as fn() -> security::Result<Value>);
}

#[test]
fn enum_and_flag_symbols_compile() {
    let _ = CodeSigningFlags::ALLOW_NETWORK_ACCESS | CodeSigningFlags::CHECK_NESTED_CODE;
    let _ = CmsSignedAttributes::SIGNING_TIME | CmsSignedAttributes::SMIME_CAPABILITIES;
    let _ = CmsCertificateChainMode::ChainWithRootOrFail;
    let _ = CmsDigestAlgorithm::Sha256;
    let _ = TrustOptions::ALLOW_EXPIRED | TrustOptions::IMPLICIT_ANCHORS;
    let _ = json!({"pid": 1});
}
