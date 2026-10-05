use sqlx::{Executor, Sqlite};

use crate::models::wasm::{CoordinatorZomeModel, DnaDefModel, EntryDefModel, IntegrityZomeModel};

/// Store WASM bytecode.
pub(super) async fn put_wasm<'e, E>(executor: E, hash: &[u8], code: &[u8]) -> sqlx::Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query("INSERT OR REPLACE INTO Wasm (hash, code) VALUES (?, ?)")
        .bind(hash)
        .bind(code)
        .execute(executor)
        .await?;

    Ok(())
}

/// Insert or replace a compiled, serialized WASM module.
pub(super) async fn put_compiled_wasm<'e, E>(
    executor: E,
    hash: &[u8],
    serialized: &[u8],
) -> sqlx::Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query("INSERT OR REPLACE INTO CompiledWasm (hash, serialized) VALUES (?, ?)")
        .bind(hash)
        .bind(serialized)
        .execute(executor)
        .await?;

    Ok(())
}

/// Insert or replace a single DNA definition row.
pub(super) async fn insert_dna_def<'e, E>(executor: E, model: &DnaDefModel) -> sqlx::Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT OR REPLACE INTO DnaDef (hash, agent, name, network_seed, properties, lineage) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&model.hash)
    .bind(&model.agent)
    .bind(&model.name)
    .bind(&model.network_seed)
    .bind(&model.properties)
    .bind(&model.lineage)
    .execute(executor)
    .await?;

    Ok(())
}

/// Delete all integrity zome rows for a given DNA hash and agent.
pub(super) async fn delete_integrity_zomes<'e, E>(
    executor: E,
    dna_hash: &[u8],
    agent: &[u8],
) -> sqlx::Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query("DELETE FROM IntegrityZome WHERE dna_hash = ? AND agent = ?")
        .bind(dna_hash)
        .bind(agent)
        .execute(executor)
        .await?;

    Ok(())
}

/// Delete all coordinator zome rows for a given DNA hash and agent.
pub(super) async fn delete_coordinator_zomes<'e, E>(
    executor: E,
    dna_hash: &[u8],
    agent: &[u8],
) -> sqlx::Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query("DELETE FROM CoordinatorZome WHERE dna_hash = ? AND agent = ?")
        .bind(dna_hash)
        .bind(agent)
        .execute(executor)
        .await?;

    Ok(())
}

/// Insert a single integrity zome row.
pub(super) async fn insert_integrity_zome<'e, E>(
    executor: E,
    model: &IntegrityZomeModel,
) -> sqlx::Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT OR REPLACE INTO IntegrityZome (dna_hash, agent, zome_index, zome_name, zome_hash, dependencies) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&model.dna_hash)
    .bind(&model.agent)
    .bind(model.zome_index)
    .bind(&model.zome_name)
    .bind(model.zome_hash.as_slice())
    .bind(&model.dependencies)
    .execute(executor)
    .await?;

    Ok(())
}

/// Insert a single coordinator zome row.
pub(super) async fn insert_coordinator_zome<'e, E>(
    executor: E,
    model: &CoordinatorZomeModel,
) -> sqlx::Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT OR REPLACE INTO CoordinatorZome (dna_hash, agent, zome_index, zome_name, zome_hash, dependencies) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&model.dna_hash)
    .bind(&model.agent)
    .bind(model.zome_index)
    .bind(&model.zome_name)
    .bind(model.zome_hash.as_slice())
    .bind(&model.dependencies)
    .execute(executor)
    .await?;

    Ok(())
}

/// Insert or replace a single entry definition row.
pub(super) async fn put_entry_def<'e, E>(executor: E, model: &EntryDefModel) -> sqlx::Result<()>
where
    E: Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "INSERT OR REPLACE INTO EntryDef (key, entry_def_id, entry_def_id_type, visibility, required_validations) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&model.key)
    .bind(&model.entry_def_id)
    .bind(&model.entry_def_id_type)
    .bind(&model.visibility)
    .bind(model.required_validations)
    .execute(executor)
    .await?;

    Ok(())
}

/// How many full sets of unreferenced WASM are kept beyond what is in use.
///
/// A set is as many rows as there are distinct WASM hashes referenced by an
/// installed DNA definition, so this keeps roughly the last three superseded
/// versions of everything installed.
pub(super) const UNREFERENCED_WASM_SETS_KEPT: i64 = 3;

/// Delete WASM that no installed DNA definition references, keeping the most
/// recently stored unreferenced rows.
///
/// A coordinator update replaces a DNA's zome rows and leaves the superseded
/// WASM and its compiled module behind, so without this the store grows by
/// one module set per update and never shrinks.
///
/// Recent unreferenced rows are kept for two reasons. An install stores its
/// WASM before the DNA definition that references it, so the newest
/// unreferenced rows may belong to an install in flight. And a recent
/// version is the one most likely to be reinstated.
///
/// Returns the number of WASM rows deleted. Freed pages are reused by later
/// writes; the file does not shrink without a `VACUUM`.
pub(super) async fn prune_unreferenced_wasm(
    conn: &mut sqlx::SqliteConnection,
) -> sqlx::Result<u64> {
    // Static strings throughout: the only variable is the bound row count.
    macro_rules! referenced {
        () => {
            "SELECT zome_hash FROM IntegrityZome UNION SELECT zome_hash FROM CoordinatorZome"
        };
    }
    macro_rules! doomed {
        () => {
            concat!(
                "SELECT hash FROM Wasm WHERE hash NOT IN (",
                referenced!(),
                ") ORDER BY rowid DESC LIMIT -1 OFFSET ?"
            )
        };
    }
    let (referenced,): (i64,) = sqlx::query_as(concat!(
        "SELECT COUNT(*) FROM Wasm WHERE hash IN (",
        referenced!(),
        ")"
    ))
    .fetch_one(&mut *conn)
    .await?;
    let keep = UNREFERENCED_WASM_SETS_KEPT * referenced.max(1);
    // Explicit, so the compiled module goes whether or not foreign keys are
    // enforced on this connection.
    sqlx::query(concat!(
        "DELETE FROM CompiledWasm WHERE hash IN (",
        doomed!(),
        ")"
    ))
    .bind(keep)
    .execute(&mut *conn)
    .await?;
    let deleted = sqlx::query(concat!("DELETE FROM Wasm WHERE hash IN (", doomed!(), ")"))
        .bind(keep)
        .execute(&mut *conn)
        .await?;
    Ok(deleted.rows_affected())
}
