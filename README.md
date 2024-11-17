# Encrypted Fields Bundle

This bundle provides a way to encrypt and decrypt fields in your Doctrine entities with a simple attribute.

You provide a single master key in your configuration and the bundle will generate a unique key for each row
in any table containing encrypted fields.

These encryption keys are stored in a separate table and are encrypted with the master key.

## Installation

Note: This package requires the OpenSSL extension.

```bash
composer require dwgebler/encrypted-fields-bundle
```

You will need to generate a migration to add the `encryption_key` table to your database:

```bash
php bin/console make:migration
```

## Usage

### Configuration

Add the following configuration to your `config/packages/gebler_encrypted_fields.yaml`:

```yaml
encrypted_fields:
  master_key: '%env(trim:file:ENCRYPTED_FIELDS_KEY)%' # or other value of your choice
  cipher: 'aes-256-gcm' # this is optional, default is 'aes-256-gcm'
```

The master key should be encoded as hexadecimal and the appropriate length for the algorithm you've chosen.

For the default algorithm, the key length is 256 bits (32 bytes).

If you are using the default algorithm, a master key file can be generated with the following command:

```bash
php -r "file_put_contents('master.key', bin2hex(random_bytes(32));"
```

### Entity

Add the `Gebler\EncryptedFieldsBundle\Attribute\EncryptedField` attribute to the fields you want to encrypt:

You can also selectively encrypt fields of arrays by using the `elements` option of the attribute.

```php
use Gebler\EncryptedFieldsBundle\Attribute\EncryptedField;

class Foo
{
    #[EncryptedField]
    private string $bar;
    
    #[EncryptedField(elements: ['baz'])]
    private array $qux;
    
    // Use the `useMasterKey` option to encrypt with the master key instead of a field-specific key
    #[EncryptedField(useMasterKey: true)]
    private string $quux;
    
    // Use the `key` option to specify a custom key
    #[EncryptedField(key: 'some_custom_key_just_for_this_property')]
    private string $corge;
}
```

### Encryption

When you persist or update an entity with encrypted fields, the bundle will automatically encrypt the fields before
inserting or updating the row in the database.

### Decryption

When you retrieve an entity with encrypted fields, the bundle will automatically decrypt the fields before
returning the entity.

