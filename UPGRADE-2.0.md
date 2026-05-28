# Upgrading from 1.x to 2.0

## Behavioural changes

1. **`preUpdate` no longer writes plain values to the database.** This was a silent data-loss bug in 1.x affecting any UPDATE of an entity carrying an `#[EncryptedField]`. After upgrading, encrypted columns hold ciphertext consistently and `postLoad` decryption stops failing intermittently for updated rows.

2. **Unchanged encrypted fields are no longer re-encrypted on flush.** Doctrine's change set now reflects plain values, so `flush()` of an unmodified entity issues no UPDATE for encrypted columns. The ciphertext IV for an unchanged column is byte-stable across flushes.

3. **Key rotation correctly handles `useMasterKey: true` and custom-`key:` fields.** In 1.x, these were re-encrypted with the per-row key during rotation, corrupting the data. If you ran rotation against a database containing such fields under 1.x, those columns are unrecoverable without restoring a backup.

4. **`EncryptedFieldsListener` and `EncryptionKeyListener` now expose `setEnabled(bool)`** to let bulk-import or migration scripts suspend the listeners.

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

## Removed / changed surface

- The internal direct-SQL `SELECT nextval('encryption_key_id_seq')` insert path is gone; `EncryptionKey` is now persisted via Doctrine ORM, which works on every DBAL platform.
- `RotateEncryptionKeyCommand` constructor takes 3 additional arguments (the configured master key as a string, and references to both listeners). The bundle's own service definition is updated; hand-rolled service users must update their wiring.
- Configuration: `cipher` is now case-insensitive (the bundle no longer needs to lowercase it before passing through).

## Verification

After running the schema migration, on a copy of your production database:

```bash
php bin/console gebler:encryption:rotate-key --generate-new-key
```

(use `--database-key=$OLD_KEY` if the configured master key has changed). Verify that all records reload without exception under the new master key. The new key will be printed at the end; save it.
