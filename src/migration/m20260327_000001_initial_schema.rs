use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
pub enum IpRecords {
    Table,
    Id,
    Address,
    IsWhitelist,
    GroupId,
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
    BoundIp,
}

#[derive(DeriveIden)]
pub enum WebhookConfigs {
    Table,
    Id,
    TargetUrl,
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
        manager
            .create_table(
                Table::create()
                    .table(IpRecords::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(IpRecords::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(IpRecords::Address).string().not_null().unique_key())
                    .col(ColumnDef::new(IpRecords::IsWhitelist).boolean().not_null())
                    .col(ColumnDef::new(IpRecords::GroupId).uuid())
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
                    .col(ColumnDef::new(ApiKeys::BoundIp).string().not_null())
                    .to_owned(),
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
        manager.drop_table(Table::drop().table(ApiKeys::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(IpRecords::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(IpGroups::Table).to_owned()).await?;
        Ok(())
    }
}
