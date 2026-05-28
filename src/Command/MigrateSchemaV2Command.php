<?php

namespace Gebler\EncryptedFieldsBundle\Command;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Platforms\MySQLPlatform;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'gebler:encryption:migrate-schema-v2',
    description: 'Idempotently migrate the encryption_key table from 1.x to 2.0 layout',
)]
class MigrateSchemaV2Command extends Command
{
    public function __construct(private readonly Connection $connection)
    {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $sm = $this->connection->createSchemaManager();
        $platform = $this->connection->getDatabasePlatform();

        // Step 1: rename legacy 'EncryptionKey' table to 'encryption_key' if applicable.
        $tables = array_map('strtolower', $sm->listTableNames());
        $hasLegacy = in_array('encryptionkey', $tables, true);
        $hasV2 = in_array('encryption_key', $tables, true);

        if ($hasLegacy && !$hasV2) {
            $rename = $this->renameTableSql($platform, 'EncryptionKey', 'encryption_key');
            $io->writeln('  ' . $rename);
            $this->connection->executeStatement($rename);
        } elseif (!$hasLegacy && !$hasV2) {
            $io->error('Neither EncryptionKey nor encryption_key table found. Has the bundle been installed?');
            return Command::FAILURE;
        }

        $table = $sm->introspectTable('encryption_key');
        $statements = [];

        // Step 2: rename 'key' column to 'encryption_key' if not already done.
        if ($table->hasColumn('key') && !$table->hasColumn('encryption_key')) {
            $statements[] = $this->renameColumnSql($platform, 'encryption_key', 'key', 'encryption_key');
        }

        // Step 3: add 'master_encrypted' if missing.
        if (!$table->hasColumn('master_encrypted')) {
            $statements[] = 'ALTER TABLE encryption_key ADD COLUMN master_encrypted BOOLEAN NOT NULL DEFAULT 1';
        }

        // Step 4: add unique (entity_class, entity_id) if missing.
        $hasUnique = false;
        foreach ($table->getIndexes() as $idx) {
            $cols = array_map('strtolower', $idx->getColumns());
            if ($idx->isUnique() && $cols === ['entity_class', 'entity_id']) {
                $hasUnique = true;
                break;
            }
        }
        if (!$hasUnique) {
            $statements[] = 'CREATE UNIQUE INDEX uniq_encryption_key_entity ON encryption_key (entity_class, entity_id)';
        }

        if ($statements === []) {
            $io->success('encryption_key is already at 2.0 layout.');
            return Command::SUCCESS;
        }

        foreach ($statements as $sql) {
            $io->writeln('  ' . $sql);
            $this->connection->executeStatement($sql);
        }

        $io->success('encryption_key migrated to 2.0 layout. NOTE: this command does NOT change column types ' .
            '(int entity_id → varchar, key → text, etc.). For column type changes please use Doctrine\'s ' .
            'orm:schema-tool:update --dump-sql to generate the diff, or write a manual migration. ' .
            'The 2.0 listener works with the old column types as long as values fit, but applying ' .
            'the recommended types prevents silent truncation.');
        return Command::SUCCESS;
    }

    private function renameTableSql(AbstractPlatform $platform, string $from, string $to): string
    {
        if ($platform instanceof MySQLPlatform) {
            return sprintf('RENAME TABLE `%s` TO `%s`', $from, $to);
        }
        // PostgreSQL, SQLite, generic SQL
        return sprintf('ALTER TABLE %s RENAME TO %s', $from, $to);
    }

    private function renameColumnSql(AbstractPlatform $platform, string $table, string $from, string $to): string
    {
        if ($platform instanceof MySQLPlatform) {
            return sprintf('ALTER TABLE `%s` RENAME COLUMN `%s` TO `%s`', $table, $from, $to);
        }
        if ($platform instanceof PostgreSQLPlatform) {
            return sprintf('ALTER TABLE %s RENAME COLUMN %s TO %s', $table, $from, $to);
        }
        if ($platform instanceof SQLitePlatform) {
            return sprintf('ALTER TABLE %s RENAME COLUMN "%s" TO "%s"', $table, $from, $to);
        }
        return sprintf('ALTER TABLE %s RENAME COLUMN %s TO %s', $table, $from, $to);
    }
}
