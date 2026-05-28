<?php

namespace Gebler\EncryptedFieldsBundle\Command;

use Doctrine\ORM\EntityManagerInterface;
use Gebler\EncryptedFieldsBundle\Doctrine\EncryptedFieldsListener;
use Gebler\EncryptedFieldsBundle\Doctrine\EncryptionKeyListener;
use Gebler\EncryptedFieldsBundle\Repository\EncryptionKeyRepository;
use Gebler\EncryptedFieldsBundle\Service\EncryptedFieldsRepository;
use Gebler\EncryptedFieldsBundle\Service\EncryptionManager;
use Gebler\EncryptedFieldsBundle\Service\EncryptionManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

#[AsCommand(
    name: 'gebler:encryption:rotate-key',
    description: 'Rotate entity encryption keys',
)]
class RotateEncryptionKeyCommand extends Command
{
    private const DEFAULT_BATCH_SIZE = 50;

    public function __construct(
        private readonly EncryptionManagerInterface $encryptionManager,
        private readonly EncryptionKeyRepository $encryptionKeyRepository,
        private readonly EncryptedFieldsRepository $encryptedFieldsRepository,
        private readonly EntityManagerInterface $em,
        private readonly ParameterBagInterface $parameterBag,
        private readonly string $configuredMasterKey,
        private readonly EncryptedFieldsListener $fieldsListener,
        private readonly EncryptionKeyListener $keyListener,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('database-key', 'k', InputOption::VALUE_OPTIONAL, 'Key for data in the database')
            ->addOption('database-key-file', 'f', InputOption::VALUE_OPTIONAL, 'Path to key for data in database')
            ->addOption('generate-new-key', 'g', InputOption::VALUE_NONE, 'Generate a new master key and output it')
            ->addOption('batch-size', null, InputOption::VALUE_REQUIRED, 'Flush/clear every N rows', (string) self::DEFAULT_BATCH_SIZE);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $dbKey = $input->getOption('database-key');
        if ($input->getOption('database-key-file')) {
            $path = (string) $input->getOption('database-key-file');
            if (!is_readable($path)) {
                $io->error('Database key file is not readable.');
                return Command::FAILURE;
            }
            $dbKey = file_get_contents($path);
        }
        $generateNewKey = (bool) $input->getOption('generate-new-key');
        $batchSize = max(1, (int) $input->getOption('batch-size'));

        if ($dbKey === null && !$generateNewKey) {
            $io->error('No database key provided and not generating a new key.');
            return Command::FAILURE;
        }

        $oldMasterKey = $dbKey ?? $this->configuredMasterKey;
        $newMasterKey = $generateNewKey ? $this->encryptionManager->createEncryptionKey() : $this->configuredMasterKey;
        $cipher = $this->encryptionManager->getCipher();
        $oldMasterManager = new EncryptionManager($oldMasterKey, $cipher);
        $newMasterManager = new EncryptionManager($newMasterKey, $cipher);

        $this->fieldsListener->setEnabled(false);
        $this->keyListener->setEnabled(false);
        $this->em->getConnection()->beginTransaction();
        try {
            $this->rotate($oldMasterManager, $newMasterManager, $batchSize);
            $this->em->getConnection()->commit();
        } catch (\Throwable $e) {
            $this->em->getConnection()->rollBack();
            $io->error('Rotation failed: ' . $e->getMessage());
            return Command::FAILURE;
        } finally {
            $this->fieldsListener->setEnabled(true);
            $this->keyListener->setEnabled(true);
        }

        $io->success('Encryption keys have been rotated.');
        if ($generateNewKey) {
            $io->success('Save the new key: ' . $newMasterKey);
        }
        return Command::SUCCESS;
    }

    private function rotate(EncryptionManager $oldMaster, EncryptionManager $newMaster, int $batchSize): void
    {
        $rows = $this->encryptionKeyRepository->findAll();
        $count = 0;

        foreach ($rows as $keyRow) {
            // Listeners are disabled, so postLoad did not decrypt the key column.
            $entityKeyPlain = $keyRow->isMasterEncrypted()
                ? $oldMaster->decryptWithMasterKey($keyRow->getKey())
                : $keyRow->getKey();

            $entity = $this->em->getRepository($keyRow->getEntityClass())
                ->find($keyRow->getEntityId());
            if ($entity === null) {
                // Orphan row — preserve it under the new master so it remains
                // decryptable if the host entity is recreated, but skip the
                // per-field pass (there's no entity to rotate fields on).
                $keyRow->setKey($newMaster->encryptWithMasterKey($entityKeyPlain));
                $keyRow->setMasterEncrypted(true);
                $this->flushIfBatch(++$count, $batchSize);
                continue;
            }

            $newEntityKeyPlain = $oldMaster->createEncryptionKey();
            $fields = $this->encryptedFieldsRepository->getFields($keyRow->getEntityClass());
            foreach ($fields as $field => $options) {
                $value = $entity->{'get' . $field}();
                if ($value === null) {
                    continue;
                }
                $value = $this->rotateValue(
                    $value, $options,
                    $oldMaster, $newMaster,
                    $entityKeyPlain, $newEntityKeyPlain,
                );
                $entity->{'set' . $field}($value);
            }
            $keyRow->setKey($newMaster->encryptWithMasterKey($newEntityKeyPlain));
            $keyRow->setMasterEncrypted(true);
            $this->flushIfBatch(++$count, $batchSize);
        }
        $this->em->flush();
    }

    private function flushIfBatch(int $count, int $batchSize): void
    {
        if ($count % $batchSize === 0) {
            $this->em->flush();
            $this->em->clear();
        }
    }

    /** @param array<string, mixed> $options */
    private function rotateValue(
        mixed $value,
        array $options,
        EncryptionManager $oldMaster,
        EncryptionManager $newMaster,
        string $oldEntityKey,
        string $newEntityKey,
    ): mixed {
        $elements = $options['elements'] ?? null;
        if (is_array($value) && $elements !== null) {
            foreach ($elements as $element) {
                if (!array_key_exists($element, $value) || $value[$element] === null) {
                    continue;
                }
                $value[$element] = $this->rotateScalar(
                    (string) $value[$element], $options,
                    $oldMaster, $newMaster, $oldEntityKey, $newEntityKey,
                );
            }
            return $value;
        }
        return $this->rotateScalar(
            (string) $value, $options,
            $oldMaster, $newMaster, $oldEntityKey, $newEntityKey,
        );
    }

    /** @param array<string, mixed> $options */
    private function rotateScalar(
        string $value,
        array $options,
        EncryptionManager $oldMaster,
        EncryptionManager $newMaster,
        string $oldEntityKey,
        string $newEntityKey,
    ): string {
        if ($options['useMasterKey'] ?? false) {
            $plain = $oldMaster->decryptWithMasterKey($value);
            return $newMaster->encryptWithMasterKey($plain);
        }
        if (($options['key'] ?? null) !== null) {
            $customKey = (string) $this->parameterBag->resolveValue($options['key']);
            // Custom keys are externally owned; we re-encrypt with the same key
            // to produce a fresh IV but keep the key identity.
            $plain = $oldMaster->decrypt($value, $customKey);
            return $newMaster->encrypt($plain, $customKey);
        }
        $plain = $oldMaster->decrypt($value, $oldEntityKey);
        return $newMaster->encrypt($plain, $newEntityKey);
    }
}
