use std::ffi::{c_char, c_void, CString};
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::rc::Rc;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{OsStatus, Result, SecurityError};

unsafe extern "C" {
    pub(crate) fn security_release_handle(pointer: *mut c_void);
    pub(crate) fn security_string_len(pointer: *mut c_void) -> isize;
    pub(crate) fn security_string_copy_utf8(
        pointer: *mut c_void,
        buffer: *mut c_char,
        capacity: isize,
    ) -> isize;
    pub(crate) fn security_data_len(pointer: *mut c_void) -> isize;
    pub(crate) fn security_data_copy_bytes(
        pointer: *mut c_void,
        buffer: *mut c_void,
        capacity: isize,
    ) -> isize;

    pub(crate) fn security_keychain_set_password(
        account: *const c_char,
        service: *const c_char,
        password: *const c_char,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_keychain_get_password(
        account: *const c_char,
        service: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_keychain_delete_password(
        account: *const c_char,
        service: *const c_char,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_keychain_list_accounts(
        service: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_access_control_get_type_id() -> usize;
    pub(crate) fn security_access_control_create(
        protection: *const c_char,
        flags: u64,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;

    pub(crate) fn security_identity_import_pkcs12_first(
        data_pointer: *const c_void,
        data_length: isize,
        password: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_identity_copy_label(pointer: *mut c_void) -> *mut c_void;
    pub(crate) fn security_identity_get_chain_count(pointer: *mut c_void) -> isize;
    pub(crate) fn security_identity_copy_certificate(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_identity_copy_private_key_attributes(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_identity_get_type_id() -> usize;
    pub(crate) fn security_identity_create(
        certificate_pointer: *mut c_void,
        private_key_pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_identity_create_with_certificate(
        certificate_pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_identity_copy_preferred(
        name: *const c_char,
        key_usage_json: *const c_char,
        valid_issuers_json: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_identity_set_preferred(
        identity_pointer: *mut c_void,
        name: *const c_char,
        key_usage_json: *const c_char,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_identity_copy_system_identity(
        domain: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_identity_copy_actual_domain(pointer: *mut c_void) -> *mut c_void;
    pub(crate) fn security_identity_set_system_identity(
        domain: *const c_char,
        identity_pointer: *mut c_void,
        error_out: *mut *mut c_void,
    ) -> OsStatus;

    pub(crate) fn security_certificate_from_der(
        data_pointer: *const c_void,
        data_length: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_import_item(
        data_pointer: *const c_void,
        data_length: isize,
        file_name_or_extension: *const c_char,
        format: u32,
        item_type: u32,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_export_item(
        pointer: *mut c_void,
        format: u32,
        pem_armour: bool,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_copy_der(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_copy_subject_summary(pointer: *mut c_void) -> *mut c_void;
    pub(crate) fn security_certificate_copy_common_name(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_copy_email_addresses(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_copy_normalized_subject_sequence(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_copy_normalized_issuer_sequence(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_copy_serial_number(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_copy_not_valid_before(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_copy_not_valid_after(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_copy_public_key(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_array_get_count(pointer: *mut c_void) -> isize;
    pub(crate) fn security_certificate_array_copy_item(
        pointer: *mut c_void,
        index: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_get_type_id() -> usize;
    pub(crate) fn security_certificate_add_to_keychain(
        pointer: *mut c_void,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_certificate_copy_values(
        pointer: *mut c_void,
        keys_json: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_copy_long_description(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_copy_short_description(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_copy_preferred(
        name: *const c_char,
        key_usage_json: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_certificate_set_preferred(
        pointer: *mut c_void,
        name: *const c_char,
        key_usage_json: *const c_char,
        error_out: *mut *mut c_void,
    ) -> OsStatus;

    pub(crate) fn security_key_get_type_id() -> usize;
    pub(crate) fn security_key_get_block_size(pointer: *mut c_void) -> isize;
    pub(crate) fn security_key_copy_external_representation(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_key_copy_attributes(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_private_key_create_with_data(
        data_pointer: *const c_void,
        data_length: isize,
        key_type: u32,
        key_size_bits: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_private_key_import_item(
        data_pointer: *const c_void,
        data_length: isize,
        file_name_or_extension: *const c_char,
        format: u32,
        item_type: u32,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_private_key_create_signature(
        pointer: *mut c_void,
        algorithm: u32,
        data_pointer: *const c_void,
        data_length: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_public_key_verify_signature(
        pointer: *mut c_void,
        algorithm: u32,
        signed_data_pointer: *const c_void,
        signed_data_length: isize,
        signature_pointer: *const c_void,
        signature_length: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> bool;
    pub(crate) fn security_public_key_create_encrypted_data(
        pointer: *mut c_void,
        algorithm: u32,
        data_pointer: *const c_void,
        data_length: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_private_key_create_decrypted_data(
        pointer: *mut c_void,
        algorithm: u32,
        data_pointer: *const c_void,
        data_length: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;

    pub(crate) fn security_policy_get_type_id() -> usize;
    pub(crate) fn security_policy_create_basic_x509(
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_policy_create_ssl(
        server: bool,
        hostname: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_policy_create_revocation(
        flags: u32,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_policy_create_with_properties(
        identifier: *const c_char,
        properties_json: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_policy_copy_properties(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;

    pub(crate) fn security_trust_create(
        certificate_pointers: *const *mut c_void,
        certificate_count: isize,
        policy_pointers: *const *mut c_void,
        policy_count: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_trust_set_policies(
        pointer: *mut c_void,
        policy_pointers: *const *mut c_void,
        policy_count: isize,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_trust_set_anchor_certificates(
        pointer: *mut c_void,
        certificate_pointers: *const *mut c_void,
        certificate_count: isize,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_trust_set_anchor_certificates_only(
        pointer: *mut c_void,
        only_anchor_certificates: bool,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_trust_set_network_fetch_allowed(
        pointer: *mut c_void,
        allowed: bool,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_trust_evaluate(
        pointer: *mut c_void,
        error_out: *mut *mut c_void,
    ) -> bool;
    pub(crate) fn security_trust_copy_result(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_trust_copy_certificate_chain(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_trust_get_type_id() -> usize;
    pub(crate) fn security_trust_copy_policies(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_trust_get_network_fetch_allowed(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> bool;
    pub(crate) fn security_trust_copy_custom_anchor_certificates(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_trust_set_verify_date(
        pointer: *mut c_void,
        unix_seconds: f64,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_trust_get_verify_time(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_trust_evaluate_async(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> bool;
    pub(crate) fn security_trust_get_trust_result(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> u32;
    pub(crate) fn security_trust_copy_key(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_trust_get_certificate_count(pointer: *mut c_void) -> isize;
    pub(crate) fn security_trust_copy_exceptions(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_trust_set_exceptions(
        pointer: *mut c_void,
        data_pointer: *const c_void,
        data_length: isize,
        error_out: *mut *mut c_void,
    ) -> bool;
    pub(crate) fn security_trust_set_ocsp_response(
        pointer: *mut c_void,
        responses_json: *const c_char,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_trust_set_signed_certificate_timestamps(
        pointer: *mut c_void,
        timestamps_json: *const c_char,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_trust_set_options(
        pointer: *mut c_void,
        options: u32,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_trust_copy_anchor_certificates(
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;

    pub(crate) fn security_authorization_create(
        flags: u32,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_authorization_make_external_form(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_authorization_create_from_external_form(
        data_pointer: *const c_void,
        data_length: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_authorization_copy_info(
        pointer: *mut c_void,
        tag: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_authorization_copy_rights(
        pointer: *mut c_void,
        rights_json: *const c_char,
        flags: u32,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_authorization_copy_rights_async(
        pointer: *mut c_void,
        rights_json: *const c_char,
        flags: u32,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;

    pub(crate) fn security_code_copy_self(
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_code_copy_static_code(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_static_code_check_validity(
        pointer: *mut c_void,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_static_code_copy_path(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_static_code_copy_designated_requirement(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_static_code_copy_signing_information(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_task_create_from_self(
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_task_copy_signing_identifier(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_task_copy_value_for_entitlement(
        pointer: *mut c_void,
        entitlement: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_code_get_type_id() -> usize;
    pub(crate) fn security_static_code_get_type_id() -> usize;
    pub(crate) fn security_requirement_get_type_id() -> usize;
    pub(crate) fn security_task_get_type_id() -> usize;
    pub(crate) fn security_requirement_create_with_data(
        data_pointer: *const c_void,
        data_length: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_requirement_create_with_string(
        text: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_requirement_create_with_string_and_errors(
        text: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_requirement_copy_data(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_requirement_copy_string(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_static_code_create_with_path(
        path: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_static_code_create_with_path_and_attributes(
        path: *const c_char,
        attributes_json: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_static_code_check_validity_with_errors(
        pointer: *mut c_void,
        flags: u32,
        requirement_pointer: *mut c_void,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_static_code_check_static_validity(
        pointer: *mut c_void,
        flags: u32,
        requirement_pointer: *mut c_void,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_static_code_check_static_validity_with_errors(
        pointer: *mut c_void,
        flags: u32,
        requirement_pointer: *mut c_void,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_code_copy_host(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_code_copy_guest_with_attributes(
        host_pointer: *mut c_void,
        attributes_json: *const c_char,
        flags: u32,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_static_code_validate_file_resource(
        pointer: *mut c_void,
        relative_path: *const c_char,
        data_pointer: *const c_void,
        data_length: isize,
        flags: u32,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_static_code_map_memory(
        pointer: *mut c_void,
        flags: u32,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_task_create_from_current_audit_token(
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_task_copy_values_for_entitlements(
        pointer: *mut c_void,
        entitlements_json: *const c_char,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;

    pub(crate) fn security_random_fill(
        buffer: *mut c_void,
        length: isize,
        error_out: *mut *mut c_void,
    ) -> OsStatus;

    pub(crate) fn security_transform_encode_base64(
        data_pointer: *const c_void,
        data_length: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_transform_decode_base64(
        data_pointer: *const c_void,
        data_length: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;

    pub(crate) fn security_secure_transport_create_client(
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_secure_transport_create_server(
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_secure_transport_set_protocol_min(
        pointer: *mut c_void,
        protocol: *const c_char,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_secure_transport_set_protocol_max(
        pointer: *mut c_void,
        protocol: *const c_char,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_secure_transport_copy_state(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;

    pub(crate) fn security_cms_decode_all_certificates(
        data_pointer: *const c_void,
        data_length: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_decoder_get_type_id() -> usize;
    pub(crate) fn security_cms_decoder_create(
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_decoder_update_message(
        pointer: *mut c_void,
        data_pointer: *const c_void,
        data_length: isize,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_cms_decoder_finalize_message(
        pointer: *mut c_void,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_cms_decoder_set_detached_content(
        pointer: *mut c_void,
        data_pointer: *const c_void,
        data_length: isize,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_cms_decoder_copy_detached_content(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_decoder_get_num_signers(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> isize;
    pub(crate) fn security_cms_decoder_copy_signer_status(
        pointer: *mut c_void,
        signer_index: isize,
        policy_pointer: *mut c_void,
        evaluate_sec_trust: bool,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_decoder_copy_signer_email_address(
        pointer: *mut c_void,
        signer_index: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_decoder_copy_signer_cert(
        pointer: *mut c_void,
        signer_index: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_decoder_is_content_encrypted(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> bool;
    pub(crate) fn security_cms_decoder_copy_encapsulated_content_type(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_decoder_copy_content(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_decoder_copy_signer_signing_time(
        pointer: *mut c_void,
        signer_index: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_decoder_copy_signer_timestamp(
        pointer: *mut c_void,
        signer_index: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_decoder_copy_signer_timestamp_with_policy(
        pointer: *mut c_void,
        policy_pointer: *mut c_void,
        signer_index: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_decoder_copy_signer_timestamp_certificates(
        pointer: *mut c_void,
        signer_index: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_encoder_get_type_id() -> usize;
    pub(crate) fn security_cms_encoder_create(
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_encoder_set_signer_algorithm(
        pointer: *mut c_void,
        algorithm: *const c_char,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_cms_encoder_add_signers(
        pointer: *mut c_void,
        identity_pointers: *const *mut c_void,
        identity_count: isize,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_cms_encoder_copy_signers(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_encoder_add_recipients(
        pointer: *mut c_void,
        certificate_pointers: *const *mut c_void,
        certificate_count: isize,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_cms_encoder_copy_recipients(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_encoder_set_has_detached_content(
        pointer: *mut c_void,
        detached_content: bool,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_cms_encoder_get_has_detached_content(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> bool;
    pub(crate) fn security_cms_encoder_set_encapsulated_content_type_oid(
        pointer: *mut c_void,
        oid: *const c_char,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_cms_encoder_copy_encapsulated_content_type(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_encoder_add_supporting_certs(
        pointer: *mut c_void,
        certificate_pointers: *const *mut c_void,
        certificate_count: isize,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_cms_encoder_copy_supporting_certs(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_encoder_add_signed_attributes(
        pointer: *mut c_void,
        signed_attributes: u32,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_cms_encoder_set_certificate_chain_mode(
        pointer: *mut c_void,
        chain_mode: u32,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_cms_encoder_get_certificate_chain_mode(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> u32;
    pub(crate) fn security_cms_encoder_update_content(
        pointer: *mut c_void,
        data_pointer: *const c_void,
        data_length: isize,
        error_out: *mut *mut c_void,
    ) -> OsStatus;
    pub(crate) fn security_cms_encoder_copy_encoded_content(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_encode_content(
        identity_pointers: *const *mut c_void,
        identity_count: isize,
        certificate_pointers: *const *mut c_void,
        certificate_count: isize,
        econtent_type_oid: *const c_char,
        detached_content: bool,
        signed_attributes: u32,
        data_pointer: *const c_void,
        data_length: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_encoder_copy_signer_timestamp(
        pointer: *mut c_void,
        signer_index: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_cms_encoder_copy_signer_timestamp_with_policy(
        pointer: *mut c_void,
        policy_pointer: *mut c_void,
        signer_index: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;

    pub(crate) fn security_key_derivation_derive_pbkdf2_sha256(
        password: *const c_char,
        salt_pointer: *const c_void,
        salt_length: isize,
        rounds: isize,
        key_size_bits: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;

    pub(crate) fn security_key_agreement_generate_p256_private_key(
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_key_copy_public_key(
        pointer: *mut c_void,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
    pub(crate) fn security_key_agreement_is_supported(pointer: *mut c_void) -> bool;
    pub(crate) fn security_key_agreement_compute_shared_secret(
        private_key_pointer: *mut c_void,
        public_key_pointer: *mut c_void,
        requested_size: isize,
        shared_info_pointer: *const c_void,
        shared_info_length: isize,
        status_out: *mut OsStatus,
        error_out: *mut *mut c_void,
    ) -> *mut c_void;
}

#[derive(Debug)]
pub(crate) struct Handle {
    raw: NonNull<c_void>,
    _not_send_sync: PhantomData<Rc<()>>,
}

impl Handle {
    pub(crate) fn from_raw(raw: *mut c_void) -> Option<Self> {
        NonNull::new(raw).map(|raw| Self {
            raw,
            _not_send_sync: PhantomData,
        })
    }

    pub(crate) fn as_ptr(&self) -> *mut c_void {
        self.raw.as_ptr()
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            security_release_handle(self.raw.as_ptr());
        }
    }
}

pub(crate) fn cstring(value: &str) -> Result<CString> {
    CString::new(value).map_err(|error| {
        SecurityError::InvalidArgument(format!("string contains interior NUL byte: {error}"))
    })
}

pub(crate) fn json_cstring<T: Serialize>(value: &T) -> Result<CString> {
    let json = serde_json::to_string(value)
        .map_err(|error| SecurityError::Serialization(format!("bridge JSON failed: {error}")))?;
    cstring(&json)
}

pub(crate) fn len_to_isize(length: usize) -> Result<isize> {
    isize::try_from(length)
        .map_err(|_| SecurityError::InvalidArgument("input exceeds bridge size limits".to_owned()))
}

pub(crate) fn optional_string(raw: *mut c_void) -> Result<Option<String>> {
    let Some(handle) = Handle::from_raw(raw) else {
        return Ok(None);
    };
    read_string(&handle).map(Some)
}

pub(crate) fn optional_data(raw: *mut c_void) -> Result<Option<Vec<u8>>> {
    let Some(handle) = Handle::from_raw(raw) else {
        return Ok(None);
    };
    read_data(&handle).map(Some)
}

pub(crate) fn optional_json<T: DeserializeOwned>(raw: *mut c_void) -> Result<Option<T>> {
    optional_string(raw)?.map_or(Ok(None), |json| parse_json(&json).map(Some))
}

pub(crate) fn required_string(
    operation: &'static str,
    raw: *mut c_void,
    status: OsStatus,
    error_raw: *mut c_void,
) -> Result<String> {
    let handle = required_handle(operation, raw, status, error_raw)?;
    read_string(&handle)
}

pub(crate) fn required_data(
    operation: &'static str,
    raw: *mut c_void,
    status: OsStatus,
    error_raw: *mut c_void,
) -> Result<Vec<u8>> {
    let handle = required_handle(operation, raw, status, error_raw)?;
    read_data(&handle)
}

pub(crate) fn required_json<T: DeserializeOwned>(
    operation: &'static str,
    raw: *mut c_void,
    status: OsStatus,
    error_raw: *mut c_void,
) -> Result<T> {
    let json = required_string(operation, raw, status, error_raw)?;
    parse_json(&json)
}

pub(crate) fn status_result(
    operation: &'static str,
    status: OsStatus,
    error_raw: *mut c_void,
) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(status_error(operation, status, error_raw)?)
    }
}

pub(crate) fn required_handle(
    operation: &'static str,
    raw: *mut c_void,
    status: OsStatus,
    error_raw: *mut c_void,
) -> Result<Handle> {
    if let Some(handle) = Handle::from_raw(raw) {
        return Ok(handle);
    }

    if status != 0 {
        Err(status_error(operation, status, error_raw)?)
    } else {
        Err(SecurityError::InvalidArgument(format!(
            "{operation} returned no object"
        )))
    }
}

pub(crate) fn status_error(
    operation: &'static str,
    status: OsStatus,
    error_raw: *mut c_void,
) -> Result<SecurityError> {
    let message = optional_string(error_raw)?.unwrap_or_else(|| format!("OSStatus {status}"));
    Ok(SecurityError::from_status(operation, status, message))
}

pub(crate) fn handle_pointer_array(handles: &[&Handle]) -> Vec<*mut c_void> {
    handles.iter().map(|handle| handle.as_ptr()).collect()
}

fn parse_json<T: DeserializeOwned>(json: &str) -> Result<T> {
    serde_json::from_str(json)
        .map_err(|error| SecurityError::Serialization(format!("invalid bridge JSON: {error}")))
}

fn read_string(handle: &Handle) -> Result<String> {
    let length =
        usize::try_from(unsafe { security_string_len(handle.as_ptr()) }).map_err(|_| {
            SecurityError::Serialization("negative string length from bridge".to_owned())
        })?;
    if length == 0 {
        return Ok(String::new());
    }

    let capacity = length
        .checked_add(1)
        .ok_or_else(|| SecurityError::Serialization("string length overflow".to_owned()))?;
    let mut buffer = vec![0_u8; capacity];
    let written = usize::try_from(unsafe {
        security_string_copy_utf8(
            handle.as_ptr(),
            buffer.as_mut_ptr().cast::<c_char>(),
            len_to_isize(capacity)?,
        )
    })
    .map_err(|_| SecurityError::Serialization("negative string write count".to_owned()))?;
    buffer.truncate(written);
    String::from_utf8(buffer).map_err(|error| {
        SecurityError::Serialization(format!("bridge string was not UTF-8: {error}"))
    })
}

fn read_data(handle: &Handle) -> Result<Vec<u8>> {
    let length = usize::try_from(unsafe { security_data_len(handle.as_ptr()) })
        .map_err(|_| SecurityError::Serialization("negative data length from bridge".to_owned()))?;
    if length == 0 {
        return Ok(Vec::new());
    }

    let mut buffer = vec![0_u8; length];
    let written = usize::try_from(unsafe {
        security_data_copy_bytes(
            handle.as_ptr(),
            buffer.as_mut_ptr().cast::<c_void>(),
            len_to_isize(length)?,
        )
    })
    .map_err(|_| SecurityError::Serialization("negative data write count".to_owned()))?;
    buffer.truncate(written);
    Ok(buffer)
}
