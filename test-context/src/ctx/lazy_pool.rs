use super::TrustifyContext;
use std::ops::{Deref, DerefMut};
use test_context::AsyncTestContext;

pub struct LazyPool<T>(pub T);

impl AsyncTestContext for LazyPool<TrustifyContext> {
    async fn setup() -> Self {
        Self(
            <TrustifyContext as AsyncTestContext>::setup()
                .await
                .0
                .lazy_pool()
                .await
                .expect("must be able to create lazy pool")
                .into(),
        )
    }

    async fn teardown(self) {
        AsyncTestContext::teardown(self.0).await;
    }
}

impl<T> Deref for LazyPool<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for LazyPool<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
