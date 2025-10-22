use super::TrustifyContext;
use std::ops::{Deref, DerefMut};
use test_context::AsyncTestContext;

pub struct ReadOnly<T>(pub T);

impl AsyncTestContext for ReadOnly<TrustifyContext> {
    async fn setup() -> Self {
        Self(
            <TrustifyContext as AsyncTestContext>::setup()
                .await
                .0
                .read_only()
                .await
                .expect("must be able to make read-only")
                .into(),
        )
    }

    async fn teardown(self) {
        AsyncTestContext::teardown(self.0).await;
    }
}

impl<T> Deref for ReadOnly<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for ReadOnly<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
