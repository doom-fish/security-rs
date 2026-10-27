use std::ffi::c_void;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};

struct State<T> {
    result: Option<Result<T, String>>,
    waker: Option<Waker>,
}

pub(super) struct Completion<T> {
    state: Arc<Mutex<State<T>>>,
}

impl<T> Completion<T> {
    pub(super) fn new() -> (Self, *mut c_void) {
        let state = Arc::new(Mutex::new(State {
            result: None,
            waker: None,
        }));
        let pointer = Arc::into_raw(Arc::clone(&state)).cast_mut().cast();
        (Self { state }, pointer)
    }

    pub(super) unsafe fn complete(pointer: *mut c_void, result: Result<T, String>) {
        let state = unsafe { Arc::from_raw(pointer.cast::<Mutex<State<T>>>()) };
        let waker = {
            let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
            state.result = Some(result);
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl<T> Future for Completion<T> {
    type Output = Result<T, String>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(result) = state.result.take() {
            return Poll::Ready(result);
        }
        if !state
            .waker
            .as_ref()
            .is_some_and(|waker| waker.will_wake(context.waker()))
        {
            state.waker = Some(context.waker().clone());
        }
        Poll::Pending
    }
}
