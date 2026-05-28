<?php

namespace Gebler\EncryptedFieldsBundle\Tests\functional;

use Doctrine\DBAL\DriverManager;
use Gebler\EncryptedFieldsBundle\Command\MigrateSchemaV2Command;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;

class MigrateSchemaV2CommandTest extends TestCase
{
    private \Doctrine\DBAL\Connection $connection;

    protected function setUp(): void
    {
        $this->connection = DriverManager::getConnection([
            'driver' => 'pdo_sqlite',
            'memory' => true,
        ]);
    }

    public function testMigratesA1xShapedTable(): void
    {
        $this->connection->executeStatement(<<<SQL
            CREATE TABLE EncryptionKey (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_class VARCHAR(1000) NOT NULL,
                entity_id INTEGER NOT NULL,
                "key" VARCHAR(1000) NOT NULL
            )
        SQL);

        $command = new MigrateSchemaV2Command($this->connection);
        $tester = new CommandTester($command);
        $tester->execute([]);
        $tester->assertCommandIsSuccessful();

        $tables = array_map('strtolower', $this->connection->createSchemaManager()->listTableNames());
        $this->assertContains('encryption_key', $tables);
        $this->assertNotContains('encryptionkey', $tables);

        $table = $this->connection->createSchemaManager()->introspectTable('encryption_key');
        $this->assertFalse($table->hasColumn('key'), 'old "key" column should be renamed');
        $this->assertTrue($table->hasColumn('encryption_key'), 'new "encryption_key" column must exist');
        $this->assertTrue($table->hasColumn('master_encrypted'), 'new master_encrypted column must exist');

        $hasUnique = false;
        foreach ($table->getIndexes() as $idx) {
            $cols = array_map('strtolower', $idx->getColumns());
            if ($idx->isUnique() && $cols === ['entity_class', 'entity_id']) {
                $hasUnique = true;
                break;
            }
        }
        $this->assertTrue($hasUnique, 'unique index on (entity_class, entity_id) must exist');
    }

    public function testIsIdempotent(): void
    {
        $this->connection->executeStatement(<<<SQL
            CREATE TABLE EncryptionKey (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_class VARCHAR(1000) NOT NULL,
                entity_id INTEGER NOT NULL,
                "key" VARCHAR(1000) NOT NULL
            )
        SQL);

        $command = new MigrateSchemaV2Command($this->connection);

        $first = new CommandTester($command);
        $first->execute([]);
        $first->assertCommandIsSuccessful();

        $second = new CommandTester($command);
        $second->execute([]);
        $second->assertCommandIsSuccessful();
        $this->assertStringContainsString('already at 2.0 layout', $second->getDisplay());
    }

    public function testPreservesExistingRows(): void
    {
        $this->connection->executeStatement(<<<SQL
            CREATE TABLE EncryptionKey (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_class VARCHAR(1000) NOT NULL,
                entity_id INTEGER NOT NULL,
                "key" VARCHAR(1000) NOT NULL
            )
        SQL);
        $this->connection->insert('EncryptionKey', [
            'entity_class' => 'App\\Foo',
            'entity_id'    => 42,
            'key'          => 'ciphertext-payload',
        ]);

        $command = new MigrateSchemaV2Command($this->connection);
        (new CommandTester($command))->execute([]);

        $row = $this->connection->fetchAssociative('SELECT entity_class, entity_id, encryption_key, master_encrypted FROM encryption_key WHERE id = 1');
        $this->assertSame('App\\Foo', $row['entity_class']);
        $this->assertSame('42', (string) $row['entity_id']);
        $this->assertSame('ciphertext-payload', $row['encryption_key']);
        $this->assertSame(1, (int) $row['master_encrypted']);
    }

    public function testFailsWhenNoTablePresent(): void
    {
        $command = new MigrateSchemaV2Command($this->connection);
        $tester = new CommandTester($command);
        $exit = $tester->execute([]);
        $this->assertNotSame(0, $exit);
        // SymfonyStyle wraps error text across lines; match without spaces to ignore wrapping.
        $this->assertStringContainsString(
            'hasthebundlebeeninstalled?',
            str_replace([' ', "\n"], '', strtolower($tester->getDisplay())),
        );
    }
}
