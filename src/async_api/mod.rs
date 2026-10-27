//! Executor-agnostic async wrappers for callback-based `Security.framework` APIs.
//!
//! Enabled with the `async` Cargo feature.
//!
//! ## Wrapped APIs
//!
//! - [`AsyncTrust::evaluate`] wraps `SecTrustEvaluateAsyncWithError`.
//! - [`AsyncAuthorization::copy_rights`] wraps `AuthorizationCopyRightsAsync`.

#![cfg(feature = "async")]

use core::ffi::c_void;
use core::marker::PhantomData;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use crate::Value;

use crate::authorization::{rights_value, Authorization, AuthorizationOptions};
use crate::bridge;
use crate::error::{status, Result, SecurityError};
use crate::trust::Trust;

mod completion;
use completion::Completion;

fn flatten_async_result<T>(result: std::result::Result<Result<T>, String>) -> Result<T> {
    result
        .map_err(SecurityError::Serialization)
        .and_then(|result| result)
}

fn bridge_status_error(
    operation: &'static str,
    status: i32,
    error_raw: *mut c_void,
) -> SecurityError {
    match bridge::status_error(operation, status, error_raw) {
        Ok(error) | Err(error) => error,
    }
}

fn trust_failure(error_raw: *mut c_void) -> SecurityError {
    match bridge::optional_string(error_raw) {
        Ok(Some(message)) => SecurityError::TrustEvaluationFailed(message),
        Ok(None) => SecurityError::TrustEvaluationFailed("trust evaluation failed".to_owned()),
        Err(error) => error,
    }
}

unsafe extern "C" fn trust_evaluate_async_cb(
    refcon: *mut c_void,
    trusted: bool,
    error_raw: *mut c_void,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let result = if trusted {
            Ok(())
        } else {
            Err(trust_failure(error_raw))
        };
        unsafe {
            Completion::<Result<()>>::complete(refcon, Ok(result));
        };
    }));
}

unsafe extern "C" fn authorization_copy_rights_async_cb(
    refcon: *mut c_void,
    value_raw: *mut c_void,
    status_raw: i32,
    error_raw: *mut c_void,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let result = if status_raw == status::SUCCESS {
            match bridge::optional_value(value_raw) {
                Ok(Some(value)) => Ok(value),
                Ok(None) => Err(SecurityError::InvalidArgument(
                    "security_authorization_copy_rights_async_start returned no authorization rights"
                        .to_owned(),
                )),
                Err(error) => Err(error),
            }
        } else {
            Err(bridge_status_error(
                "security_authorization_copy_rights_async_start",
                status_raw,
                error_raw,
            ))
        };
        unsafe {
            Completion::<Result<Value>>::complete(refcon, Ok(result));
        };
    }));
}

/// Future returned by [`AsyncTrust::evaluate`].
pub struct TrustEvaluateFuture<'a> {
    inner: Completion<Result<()>>,
    _owner: PhantomData<&'a Trust>,
}

impl core::fmt::Debug for TrustEvaluateFuture<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrustEvaluateFuture")
            .finish_non_exhaustive()
    }
}

impl Future for TrustEvaluateFuture<'_> {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx).map(flatten_async_result)
    }
}

/// Future returned by [`AsyncAuthorization::copy_rights`].
pub struct AuthorizationRightsFuture<'a> {
    inner: Completion<Result<Value>>,
    _owner: PhantomData<&'a Authorization>,
}

impl core::fmt::Debug for AuthorizationRightsFuture<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthorizationRightsFuture")
            .finish_non_exhaustive()
    }
}

impl Future for AuthorizationRightsFuture<'_> {
    type Output = Result<Value>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx).map(flatten_async_result)
    }
}

/// Borrowed async wrapper for `SecTrustRef` evaluation.
#[derive(Debug, Clone, Copy)]
pub struct AsyncTrust<'a> {
    trust: &'a Trust,
}

impl<'a> AsyncTrust<'a> {
    /// Create a borrowed async wrapper around a trust object.
    #[must_use]
    pub const fn new(trust: &'a Trust) -> Self {
        Self { trust }
    }

    /// Start `SecTrustEvaluateAsyncWithError` and await its callback.
    pub fn evaluate(&self) -> Result<TrustEvaluateFuture<'a>> {
        let (inner, refcon) = Completion::<Result<()>>::new();
        let mut error_raw = ptr::null_mut();
        let status = unsafe {
            bridge::security_trust_evaluate_async_start(
                self.trust.as_ptr(),
                refcon,
                Some(trust_evaluate_async_cb),
                &raw mut error_raw,
            )
        };
        if status != status::SUCCESS {
            let error =
                bridge_status_error("security_trust_evaluate_async_start", status, error_raw);
            unsafe {
                Completion::<Result<()>>::complete(refcon, Err(error.to_string()));
            };
            drop(inner);
            return Err(error);
        }

        Ok(TrustEvaluateFuture {
            inner,
            _owner: PhantomData,
        })
    }
}

/// Borrowed async wrapper for `AuthorizationRef` rights requests.
#[derive(Debug, Clone, Copy)]
pub struct AsyncAuthorization<'a> {
    authorization: &'a Authorization,
}

impl<'a> AsyncAuthorization<'a> {
    /// Create a borrowed async wrapper around an authorization handle.
    #[must_use]
    pub const fn new(authorization: &'a Authorization) -> Self {
        Self { authorization }
    }

    /// Start `AuthorizationCopyRightsAsync` and await the authorized-rights payload.
    pub fn copy_rights(
        &self,
        rights: &[&str],
        options: AuthorizationOptions,
    ) -> Result<AuthorizationRightsFuture<'a>> {
        let rights_value = rights_value(rights)?;
        let (inner, refcon) = Completion::<Result<Value>>::new();
        let mut error_raw = ptr::null_mut();
        let status = unsafe {
            bridge::security_authorization_copy_rights_async_start(
                self.authorization.as_ptr(),
                rights_value.as_ptr(),
                options.bits(),
                refcon,
                Some(authorization_copy_rights_async_cb),
                &raw mut error_raw,
            )
        };
        if status != status::SUCCESS {
            let error = bridge_status_error(
                "security_authorization_copy_rights_async_start",
                status,
                error_raw,
            );
            unsafe {
                Completion::<Result<Value>>::complete(refcon, Err(error.to_string()));
            };
            drop(inner);
            return Err(error);
        }

        Ok(AuthorizationRightsFuture {
            inner,
            _owner: PhantomData,
        })
    }
}
