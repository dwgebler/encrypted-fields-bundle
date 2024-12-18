# Encrypted Fields Bundle

This bundle provides a way to encrypt and decrypt fields in your Doctrine entities with a simple attribute.

You provide a single master key in your configuration and the bundle will generate a unique key for each row
in any table containing encrypted fields.

These encryption keys are stored in a separate table and are encrypted with the master key.

## Installation

Note: This package requires the OpenSSL extension.

Configure the Flex recipe repository:

This step is optional, however without it, you will need to create the configuration file detailed in the Configuration 
section manually, before installing the package.

In your project's `composer.json`, add the following entry, or if you already
have a `symfony.extra.endpoint` entry, add the URL to the list.

```json
    "extra": {
        "symfony": {
          "endpoint": [
               "https://api.github.com/repos/dwgebler/flex-recipes/contents/index.json",
               "flex://defaults"
            ]
        }
    }
```

Install the package:

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
php -r "file_put_contents('master.key', bin2hex(random_bytes(32)));"
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

### Key Rotation

If you need to rotate the master key, you can do so by running the following command:

```bash
php bin/console gebler:encryption:rotate-key --generate-new-key
```

This will generate a new master key and re-encrypt all the data in the database with new keys.
The new key will be output to the console at the end of the process.

If you need to apply a known decryption key (for example, you've taken a database backup from a different environment),
you can do so by running the following command:

```bash
php bin/console gebler:encryption:rotate-key --database-key=<key>
```

Where `<key>` is the hexadecimal representation of the key you want to apply. Or, to use a key in a file:

```bash
php bin/console gebler:encryption:rotate-key --database-key-file=/path/todatabase.key
```

These commands will decrypt all the data in the database with the database key supplied and re-encrypt with
the configured application master key.

You can combine the two options above with `--generate-new-key` to generate a new master key also:

```bash
php bin/console gebler:encryption:rotate-key --generate-new-key --database-key=<key>
```

