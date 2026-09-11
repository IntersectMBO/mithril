//! Migration module
//!
use mithril_persistence::database::SqlMigration;

/// Get all the migrations required by this version of the software.
/// There shall be one migration per database version. There could be several
/// statements per migration.
pub fn get_migrations() -> Vec<SqlMigration> {
    vec![
        SqlMigration::new_squashed(
            29,
            "2445.0",
            r#"
create table if not exists signed_entity_type (
    signed_entity_type_id       integer     not null,
    name                        text        not null,
    primary key (signed_entity_type_id)
);
insert into signed_entity_type (signed_entity_type_id, name)
    values  (0, 'Mithril Stake Distribution'),
            (1, 'Cardano Stake Distribution'),
            (2, 'Full Cardano Immutable Files'),
            (3, 'Cardano Transactions');

create table if not exists signer (
    signer_id                   text        not null,
    pool_ticker                 text,
    created_at                  text        not null,
    updated_at                  text        not null,
    last_registered_at          text        null,
    primary key (signer_id)
);

create table if not exists epoch_setting (
    epoch_setting_id                    integer     not null,
    protocol_parameters                 json        not null,
    cardano_transactions_signing_config json        not null,
    primary key (epoch_setting_id)
);

create table if not exists signer_registration (
    signer_id                   text        not null,
    epoch_setting_id            integer     not null,
    verification_key            text        not null,
    verification_key_signature  text,
    operational_certificate     text,
    kes_period                  integer,
    stake                       integer,
    created_at                  text        not null,
    primary key (epoch_setting_id, signer_id)
    foreign key (epoch_setting_id) references epoch_setting(epoch_setting_id)
    foreign key (signer_id) references signer(signer_id)
);
create index signer_registration_epoch_setting_id_index on signer_registration(epoch_setting_id);
create index signer_registration_signer_id_index on signer_registration(signer_id);

create table if not exists open_message (
    open_message_id         text    not null,
    epoch_setting_id        int     not null,
    beacon                  json    not null,
    signed_entity_type_id   int     not null,
    created_at              text    not null,
    protocol_message        json    not null,
    is_certified            bool    not null default false,
    is_expired              bool    not null default false,
    expires_at              text    null,
    primary key (open_message_id),
    foreign key (epoch_setting_id)     references epoch_setting (epoch_setting_id),
    foreign key (signed_entity_type_id) references signed_entity_type (signed_entity_type_id)
);
create unique index open_message_unique_index on open_message(signed_entity_type_id, beacon);
create index open_message_epoch_setting_id_index on open_message(epoch_setting_id);
create index open_message_signed_entity_type_id_index on open_message(signed_entity_type_id);

create table if not exists single_signature (
    open_message_id                 text        not null,
    signer_id                       text        not null,
    registration_epoch_setting_id   integer     not null,
    lottery_indexes                 json        not null,
    signature                       text        not null,
    created_at                      text        not null,
    primary key (open_message_id, signer_id, registration_epoch_setting_id)
    foreign key (open_message_id) references open_message(open_message_id) on delete cascade
    foreign key (signer_id, registration_epoch_setting_id) references signer_registration(signer_id, epoch_setting_id)
);
create index single_signature_open_message_id_index on single_signature(open_message_id);
create index single_signature_signer_id_index on single_signature(signer_id);
create index single_signature_registration_epoch_setting_id_index on single_signature(registration_epoch_setting_id);

create table if not exists buffered_single_signature (
    signed_entity_type_id           integer     not null,
    party_id                        text        not null,
    lottery_indexes                 json        not null,
    signature                       text        not null,
    created_at                      text        not null,
    primary key (signed_entity_type_id, party_id)
);
create index buffered_single_signature_signed_entity_type_id on buffered_single_signature(signed_entity_type_id);
create index buffered_single_signature_party_id_index on buffered_single_signature(party_id);

create table if not exists certificate (
    certificate_id              text     not null,
    parent_certificate_id       text,
    message                     text     not null,
    signature                   text     not null,
    aggregate_verification_key  text     not null,
    epoch                       integer  not null,
    network                     text     not null,
    signed_entity_type_id       integer  not null,
    signed_entity_beacon        json     not null,
    protocol_version            text     not null,
    protocol_parameters         json     not null,
    protocol_message            json     not null,
    signers                     json     not null,
    initiated_at                text     not null,
    sealed_at                   text     not null,
    primary key (certificate_id),
    foreign key (parent_certificate_id) references certificate(certificate_id)
    foreign key (signed_entity_type_id) references signed_entity_type(signed_entity_type_id)
);
create index epoch_index on certificate(epoch);
create index certificate_parent_certificate_id_index on certificate(parent_certificate_id);

create table if not exists signed_entity (
    signed_entity_id            text        not null,
    signed_entity_type_id       integer     not null,
    certificate_id              text        not null,
    beacon                      json        not null,
    created_at                  text        not null,
    artifact                    json        not null,
    primary key (signed_entity_id)
    foreign key (signed_entity_type_id) references signed_entity_type(signed_entity_type_id)
    foreign key (certificate_id) references certificate(certificate_id)
);
create index signed_entity_signed_entity_type_id_index on signed_entity(signed_entity_type_id);
create index signed_entity_certificate_id_index on signed_entity(certificate_id);
create unique index signed_entity_unique_index on signed_entity(signed_entity_type_id, beacon);

create table if not exists pending_certificate (
    key_hash                    text     primary key,
    key                         json     not null,
    value                       json     not null
);

create table if not exists stake_pool (
    stake_pool_id text      not null,
    epoch         integer   not null,
    stake         integer   not null,
    created_at    text      not null,
    primary key (epoch, stake_pool_id)
);
        "#,
        ),
        // Migration 30
        // Alter `signed_entity` table to add `network` in `artifact` JSON field (for snapshot only).
        SqlMigration::new(
            30,
            r#"
update signed_entity
    set artifact = json_insert(
        json_insert(
            artifact,
            '$.network', 
            json_extract(beacon, '$.network'))
    ) 
where signed_entity.signed_entity_type_id = 2;
        "#,
        ),
        // Migration 31
        // Remove `network` from cardano immutable files full beacons in `open_message`,
        // `signed_entity`, and `certificate` tables
        SqlMigration::new(
            31,
            r#"
update open_message
    set beacon = json_remove(beacon, '$.network')
    where open_message.signed_entity_type_id = 2;

update signed_entity
    set beacon = json_remove(beacon, '$.network'),
        artifact = json_remove(artifact, '$.beacon.network')
    where signed_entity.signed_entity_type_id = 2;

update certificate
    set signed_entity_beacon = json_remove(signed_entity_beacon, '$.network')
    where certificate.signed_entity_type_id = 2;
        "#,
        ),
        // Migration 32
        // Add the `signed_entity_type` record for 'CardanoDatabase'
        SqlMigration::new(
            32,
            r#"
insert into signed_entity_type (signed_entity_type_id, name) 
    values  (4, 'Cardano Database');
        "#,
        ),
        // Migration 33
        // Add the `certificate_pending` table and migration data from the previous
        // `certificate_pending` JSON format.
        SqlMigration::new(
            33,
            r#"
create table new_pending_certificate (
    epoch                           integer     not null,
    pending_certificate             text        not null,
    created_at                      text        not null,
    primary key (epoch)
);
create table if not exists pending_certificate (key_hash text primary key, key json not null, value json not null);
insert into new_pending_certificate (epoch, pending_certificate, created_at) 
    select 
        json_extract(pending_certificate.value, '$.epoch') as epoch,
        pending_certificate.value, 
        strftime('%Y-%m-%dT%H:%M:%fZ', current_timestamp)
    from pending_certificate;

drop table pending_certificate;
alter table new_pending_certificate rename to pending_certificate;
        "#,
        ),
        // Migration 34
        // Add the `immutable_file_digest` table.
        SqlMigration::new(
            34,
            r#"
create table immutable_file_digest (
    immutable_file_name     text    not null,
    digest                  text    not null,
    primary key (immutable_file_name)
);
        "#,
        ),
        // Migration 35
        // Remove `pending_certificate` table.
        SqlMigration::new(
            35,
            r#"
drop table pending_certificate;
        "#,
        ),
        // Migration 36
        // Add `epoch` virtual column to `signed_entity` table.
        //
        // Note: because the epoch in the `beacon` field can be either stored directly as an integer
        // or as a JSON property, we need to use a coalesce function to get the epoch value.
        SqlMigration::new(
            36,
            r#"
alter table signed_entity add column epoch as (coalesce(json_extract(beacon, '$.epoch'), beacon));
create index signed_entity_epoch on signed_entity(epoch);
        "#,
        ),
        // Migration 37
        // Update `epoch_setting` table to make `cardano_transactions_signing_config` optional.
        SqlMigration::new(
            37,
            r#"
-- disable foreign keys since `signer_registration` has a foreign key constraint on `epoch_setting`
pragma foreign_keys=false;

create table if not exists new_epoch_setting (
    epoch_setting_id                    integer     not null,
    protocol_parameters                 json        not null,
    cardano_transactions_signing_config json,
    primary key (epoch_setting_id)
);
insert into new_epoch_setting (epoch_setting_id, protocol_parameters, cardano_transactions_signing_config)
    select epoch_setting_id, protocol_parameters, cardano_transactions_signing_config
    from epoch_setting order by rowid asc;
drop table epoch_setting;
alter table new_epoch_setting rename to epoch_setting;

-- reenable foreign keys
pragma foreign_key_check;
pragma foreign_keys=true;
        "#,
        ),
        // Migration 38
        // Add the `signed_entity_type` record for 'CardanoBlocksTransactions'
        SqlMigration::new(
            38,
            r#"
insert into signed_entity_type (signed_entity_type_id, name)
    values  (5, 'Cardano Blocks and Transactions');
        "#,
        ),
        // Migration 39
        // Add `cardano_blocks_transactions_signing_config` column to `epoch_setting` table.
        SqlMigration::new(
            39,
            r#"
alter table epoch_setting add column cardano_blocks_transactions_signing_config json;
        "#,
        ),
        // Migration 40
        // Add SNARK verification key columns to `signer_registration` table.
        SqlMigration::new(
            40,
            r#"
alter table signer_registration add column verification_key_for_snark text;
alter table signer_registration add column verification_key_signature_for_snark text;
        "#,
        ),
        // Migration 41
        // Add `aggregate_verification_key_snark` column to `certificate` table.
        SqlMigration::new(
            41,
            r#"
alter table certificate add column aggregate_verification_key_snark text;
        "#,
        ),
        // Migration 42
        // Delete blocks and transactions `signed_entity` and related `certificate` records
        // since beacon has been modified to include the block_number_offset
        SqlMigration::new(
            42,
            r#"
delete from signed_entity where signed_entity.signed_entity_type_id = 5;
delete from certificate where certificate.signed_entity_type_id = 5;
        "#,
        ),
        // Migration 43
        // Drop support for `CardanoImmutableFilesFull` signed entity type.
        SqlMigration::new(
            43,
            r#"
delete from signed_entity where signed_entity.signed_entity_type_id = 2;
delete from certificate where certificate.signed_entity_type_id = 2;
delete from open_message where open_message.signed_entity_type_id = 2;
delete from buffered_single_signature where buffered_single_signature.signed_entity_type_id = 2;
delete from signed_entity_type where signed_entity_type.signed_entity_type_id = 2;
        "#,
        ),
        // Migration 44
        // Add `ancillary_prover_data` and `ancillary_verifier_data` columns to `certificate` table.
        SqlMigration::new(
            44,
            r#"
alter table certificate add column ancillary_prover_data text;
alter table certificate add column ancillary_verifier_data text;
        "#,
        ),
        // Migration 45
        // Add Proof of Bound Possession of the SNARK signing key columns to `signer_registration` table.
        SqlMigration::new(
            45,
            r#"
alter table signer_registration add column proof_of_bound_possession_for_snark text;
        "#,
        ),
    ]
}
