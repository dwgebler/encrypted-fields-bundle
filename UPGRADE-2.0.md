# Upgrading from 1.x to 2.0

## Behavioural changes

1. **Unchanged encrypted fields are no longer re-encrypted on flush.** Doctrine's change set now reflects plain values, so `flush()` of an unmodified entity issues no UPDATE for encrypted columns. The ciphertext IV for an unchanged column is byte-stable across flushes.

2. **Key rotation correctly handles `useMasterKey: true` and custom-`key:` fields.** In 1.x, these were re-encrypted with the per-row key during rotation, corrupting the data. If you ran rotation against a database containing such fields under 1.x, those columns are unrecoverable without restoring a backup.

3. **`EncryptedFieldsListener` and `EncryptionKeyListener` now expose `setEnabled(bool)`** to let bulk-import or migration scripts suspend the listeners.

4. **`EncryptedFieldsListener` subscribes to `postUpdate` in 2.0** (a no-op handler — the listener uses `PreUpdateEventArgs::setNewValue` to feed ciphertext into the change set, so `postUpdate` has no work to do). 1.x did not subscribe to `postUpdate` at all. Relevant only if you decorate or extend the listener.

## Required actions

1. `composer require dwgebler/encrypted-fields-bundle:^2.0`
2. Schema migration: run `php bin/console gebler:encryption:migrate-schema-v2`. It is idempotent and applies only the lossless schema changes (table rename, column rename, add column, add unique index). For column-type changes (int → varchar entity_id, key → TEXT), generate a manual migration using `doctrine:schema:update --dump-sql` or write one by hand.
3. **No application code changes are required.** The `#[EncryptedField]` attribute API is unchanged.

## Database schema changes

| Column / Object | 1.x | 2.0 |
|---|---|---|
| Table name | `EncryptionKey` (Doctrine class-name default) | `encryption_key` (explicit) |
| `id` | sequence-generated `INT` | identity-generated `BIGINT` |
| `entity_class` | `VARCHAR(1000)` | `VARCHAR(255)` |
| `entity_id` | `INT` | `VARCHAR(255)` |
| `key` | `VARCHAR(1000)` | renamed to `encryption_key TEXT` |
| `master_encrypted` | (absent — flag was non-durable) | `BOOLEAN NOT NULL` |
| unique `(entity_class, entity_id)` | none | added |

## Public API additions

- `EncryptionManagerInterface::getCipher()` and `::getKeyLengthBytes()`.
- `EncryptionKeyRepository::findOneByEntity(string $class, string $id)`.
- `EncryptedFieldsListener::setEnabled(bool)` and `EncryptionKeyListener::setEnabled(bool)`.
- `Exception\InvalidEncryptedDataException` and `Exception\InvalidEncryptionKeyException` (both extend `EncryptedFieldException`). `EncryptionManager` no longer throws `InvalidArgumentException` from `encrypt`/`decrypt` (constructor still does so for unsupported cipher).

## Verification

After running the schema migration, on a copy of your production database:

```bash
php bin/console gebler:encryption:rotate-key --generate-new-key
```

(use `--database-key=$OLD_KEY` if the configured master key has changed). Verify that all records reload without exception under the new master key. The new key will be printed at the end; save it.
