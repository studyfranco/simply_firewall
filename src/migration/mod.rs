//! Database migration registry for `simply_ip_vault`. Migrations run automatically on startup.
pub use sea_orm_migration::prelude::*;

mod m20230101_000001_initial_schema;
mod m20260729_000002_add_api_key_signing_secret;
mod m20260730_000003_add_webhook_signature_mode;
mod m20260730_000004_add_webhook_auth_modes;
mod m20260801_000005_add_ip_record_soft_delete;

/// The ordered set of all schema migrations for `simply_ip_vault`.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230101_000001_initial_schema::Migration),
            Box::new(m20260729_000002_add_api_key_signing_secret::Migration),
            Box::new(m20260730_000003_add_webhook_signature_mode::Migration),
            Box::new(m20260730_000004_add_webhook_auth_modes::Migration),
            Box::new(m20260801_000005_add_ip_record_soft_delete::Migration),
        ]
    }
}
