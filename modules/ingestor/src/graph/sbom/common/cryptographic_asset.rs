use sea_orm::{ConnectionTrait, DbErr};

#[derive(Default)]
pub struct CryptographicAssetCreator {}

impl CryptographicAssetCreator {
    pub fn add(&mut self, _node_id: String) {
        // TODO
    }

    pub async fn create(self, _db: &impl ConnectionTrait) -> Result<(), DbErr> {
        Ok(())
    }
}
