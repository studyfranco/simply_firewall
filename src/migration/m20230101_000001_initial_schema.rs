use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
pub enum IpRecords {
    Table,
    Id,
    Address,
    IsWhitelist,
    GroupId,
    Cause,
    IsLocked,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum IpGroups {
    Table,
    Id,
    Name,
}

#[derive(DeriveIden)]
pub enum ApiKeys {
    Table,
    Id,
    KeyHash,
    Name,
    BoundIps,
    IsMaster,
    CanManageKeys,
    CanManageWebhooks,
    CanCreateGroups,
}

#[derive(DeriveIden)]
pub enum ApiKeyGroupPermissions {
    Table,
    ApiKeyId,
    GroupId,
    CanRead,
    CanWrite,
    CanDelete,
}

#[derive(DeriveIden)]
pub enum WebhookConfigs {
    Table,
    Id,
    TargetUrl,
    TriggerEvents,
    AuthHeaderName,
    AuthToken,
    PayloadTemplate,
    GroupId,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create ip_groups table
        manager
            .create_table(
                Table::create()
                    .table(IpGroups::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(IpGroups::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(IpGroups::Name).string().not_null().unique_key())
                    .to_owned(),
            )
            .await?;

        // Create ip_records table
        // Note: Unique constraint on Address to allow on_conflict (upsert) later
        manager
            .create_table(
                Table::create()
                    .table(IpRecords::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(IpRecords::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(IpRecords::Address).string().not_null().unique_key())
                    .col(ColumnDef::new(IpRecords::IsWhitelist).boolean().not_null())
                    .col(ColumnDef::new(IpRecords::GroupId).uuid())
                    .col(ColumnDef::new(IpRecords::Cause).string())
                    .col(ColumnDef::new(IpRecords::IsLocked).boolean().not_null().default(false))
                    .col(ColumnDef::new(IpRecords::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(IpRecords::UpdatedAt).date_time().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-ip_records-group_id")
                            .from(IpRecords::Table, IpRecords::GroupId)
                            .to(IpGroups::Table, IpGroups::Id)
                            .on_delete(ForeignKeyAction::SetNull)
                            .on_update(ForeignKeyAction::NoAction),
                    )
                    .to_owned(),
            )
            .await?;

        // Create api_keys table
        manager
            .create_table(
                Table::create()
                    .table(ApiKeys::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(ApiKeys::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(ApiKeys::KeyHash).string().not_null())
                    .col(ColumnDef::new(ApiKeys::Name).string().not_null())
                    .col(ColumnDef::new(ApiKeys::BoundIps).string().not_null())
                    .col(ColumnDef::new(ApiKeys::IsMaster).boolean().not_null().default(false))
                    .col(ColumnDef::new(ApiKeys::CanManageKeys).boolean().not_null().default(false))
                    .col(ColumnDef::new(ApiKeys::CanManageWebhooks).boolean().not_null().default(false))
                    .col(ColumnDef::new(ApiKeys::CanCreateGroups).boolean().not_null().default(false))
                    .to_owned(),
            )
            .await?;

        // Create api_key_group_permissions junction table
        manager
            .create_table(
                Table::create()
                    .table(ApiKeyGroupPermissions::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(ApiKeyGroupPermissions::ApiKeyId).uuid().not_null())
                    .col(ColumnDef::new(ApiKeyGroupPermissions::GroupId).uuid().not_null())
                    .col(ColumnDef::new(ApiKeyGroupPermissions::CanRead).boolean().not_null().default(false))
                    .col(ColumnDef::new(ApiKeyGroupPermissions::CanWrite).boolean().not_null().default(false))
                    .col(ColumnDef::new(ApiKeyGroupPermissions::CanDelete).boolean().not_null().default(false))
                    .primary_key(
                        Index::create()
                            .name("pk-api_key_group_permissions")
                            .col(ApiKeyGroupPermissions::ApiKeyId)
                            .col(ApiKeyGroupPermissions::GroupId)
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-akgp-api_key_id")
                            .from(ApiKeyGroupPermissions::Table, ApiKeyGroupPermissions::ApiKeyId)
                            .to(ApiKeys::Table, ApiKeys::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-akgp-group_id")
                            .from(ApiKeyGroupPermissions::Table, ApiKeyGroupPermissions::GroupId)
                            .to(IpGroups::Table, IpGroups::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned()
            )
            .await?;

        // Create webhook_configs table
        manager
            .create_table(
                Table::create()
                    .table(WebhookConfigs::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(WebhookConfigs::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(WebhookConfigs::TargetUrl).string().not_null())
                    .col(ColumnDef::new(WebhookConfigs::TriggerEvents).string().not_null().default("ban,white,delete"))
                    .col(ColumnDef::new(WebhookConfigs::AuthHeaderName).string())
                    .col(ColumnDef::new(WebhookConfigs::AuthToken).string())
                    .col(ColumnDef::new(WebhookConfigs::PayloadTemplate).string().not_null())
                    .col(ColumnDef::new(WebhookConfigs::GroupId).uuid())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-webhook_configs-group_id")
                            .from(WebhookConfigs::Table, WebhookConfigs::GroupId)
                            .to(IpGroups::Table, IpGroups::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::NoAction),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(WebhookConfigs::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(ApiKeyGroupPermissions::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(ApiKeys::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(IpRecords::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(IpGroups::Table).to_owned()).await?;
        Ok(())
    }
}
