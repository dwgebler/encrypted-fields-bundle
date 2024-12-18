<?php

namespace Gebler\EncryptedFieldsBundle\Command;

use Gebler\EncryptedFieldsBundle\Repository\EncryptionKeyRepository;
use Gebler\EncryptedFieldsBundle\Service\EncryptedFieldsRepository;
use Gebler\EncryptedFieldsBundle\Service\EncryptionManagerInterface;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Attribute\AsCommand;use Symfony\Component\Console\Command\Command;
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
    public function __construct(
        private EncryptionManagerInterface $encryptionManager,
        private EncryptionKeyRepository $encryptionKeyRepository,
        private EncryptedFieldsRepository $encryptedFieldsRepository,
        private EntityManagerInterface $em,
        private ParameterBagInterface $parameterBag,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $help = <<<'EOT'
The <info>%command.name%</info> command rotates entity encryption keys.

This command can be used to either decrypt all data with the existing master key and re-encrypt with a new master key,
or to decrypt all data with a provided master key and re-encrypt with either the existing master key or a new key.

The latter option is useful if you have taken a copy of a database and want to re-encode its encrypted fields with an
existing master key, or if you have a new master key and want to re-encode the data with that key.

If you provide a database key, the command will decrypt all data with that key and re-encrypt with either the existing
master key or a new key, depending on whether the <info>--generate-new-key</info> option is set.

If you do not provide a database key, the command will decrypt all data with the existing master key and re-encrypt with
a new master key, which will be output at the end.

TLDR; data in database doesn't match your configured application master key; run this command with either the 
<info>--database-key</info> option or the <info>--database-key-file</info> option to re-encrypt the data with the correct key.

Data in database matches your configured application master key, but you want to change it; run this command with the
<info>--generate-new-key</info> option to re-encrypt the data with a new key.
EOT;

        $this
            ->addOption('database-key', 'k', InputOption::VALUE_OPTIONAL, 'Key for data in the database')
            ->addOption('database-key-file', 'f', InputOption::VALUE_OPTIONAL, 'Path to key for data in database')
            ->addOption('generate-new-key', 'g', InputOption::VALUE_NONE, 'Generate a new key and output it at the end')
            ->setHelp($help)
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $dbKey = null;
        $generateNewKey = false;

        if ($input->getOption('database-key')) {
            $dbKey = $input->getOption('database-key');
        }

        if ($input->getOption('database-key-file')) {
            if (!is_readable($input->getOption('database-key-file'))) {
                $io->error('Database key file is not readable.');
                return Command::FAILURE;
            }
            $dbKey = file_get_contents($input->getOption('database-key-file'));
        }

        if ($input->getOption('generate-new-key')) {
            $generateNewKey = true;
        }

        if ($dbKey === null && !$generateNewKey) {
            $io->error('No database key provided and not generating a new key.');
            return Command::FAILURE;
        }

        $eventManager = $this->em->getEventManager();
        $listeners = $eventManager->getAllListeners();

        foreach ($listeners as $eventName => $eventListeners) {
            foreach ($eventListeners as $listener) {
                $eventManager->removeEventListener($eventName, $listener);
            }
        }

        $this->em->getConnection()->beginTransaction();
        try {
            if ($dbKey === null) {
                $newKey = $this->rotateWithNewKey();
            } else {
                $newKey = $this->rotateWithExistingKey($dbKey, $generateNewKey);
            }
            $this->em->getConnection()->commit();
        } catch (\Exception $e) {
            $this->em->getConnection()->rollBack();
            $io->error('An error occurred while rotating encryption keys: ' . $e->getMessage());
            $io->error('All changes have been rolled back.');
            return Command::FAILURE;
        }

        $io->success('Encryption keys have been rotated.');

        if ($newKey) {
            $io->success('Save the new key: ' . $newKey);
        }

        return Command::SUCCESS;
    }

    private function rotateWithNewKey(): ?string
    {
        $newMasterKey = $this->encryptionManager->createEncryptionKey();
        $encryptedEntities = $this->encryptionKeyRepository->findAll();

        foreach ($encryptedEntities as $encryptedEntity) {
            $entityKey = $this->encryptionManager->decryptWithMasterKey($encryptedEntity->getKey());
            $fields = $this->encryptedFieldsRepository->getFields($encryptedEntity->getEntityClass());
            $entity = $this->em->getRepository($encryptedEntity->getEntityClass())->find($encryptedEntity->getEntityId());
            $newRecordKey = $this->encryptionManager->createEncryptionKey();
            foreach ($fields as $field => $options) {
                if (isset($options['key'])) {
                    $options['key'] = $this->parameterBag->resolveValue($options['key']);
                }
                $key = $options['key'] ?? $entityKey;
                $useMasterKey = $options['useMasterKey'] ?? false;
                $elements = $options['elements'] ?? null;
                $fieldValue = $entity->{'get' . $field}();
                if ($fieldValue === null) {
                    continue;
                }
                if (is_array($fieldValue) && $elements !== null) {
                    foreach ($elements as $element) {
                        $value = $fieldValue[$element] ?? null;
                        if ($value === null) {
                            continue;
                        }
                        if ($useMasterKey) {
                            $fieldValue[$element] = $this->encryptionManager->decryptWithMasterKey($value);
                        } else {
                            $fieldValue[$element] = $this->encryptionManager->decrypt($value, $key);
                        }
                        $fieldValue[$element] = $this->encryptionManager->encrypt($fieldValue[$element], $newRecordKey);
                    }
                    $entity->{'set' . $field}($fieldValue);
                    continue;
                }
                if ($useMasterKey) {
                    $fieldValue = $this->encryptionManager->decryptWithMasterKey($fieldValue);
                } else {
                    $fieldValue = $this->encryptionManager->decrypt($fieldValue, $key);
                }
                $fieldValue = $this->encryptionManager->encrypt($fieldValue, $newRecordKey);
                $entity->{'set' . $field}($fieldValue);
            }
            $encryptedEntity->setKey($this->encryptionManager->encrypt($newRecordKey, $newMasterKey));
            $this->em->flush();
        }
        return $newMasterKey;
    }

    private function rotateWithExistingKey(string $dbKey, bool $generateNewKey): ?string
    {
        $newMasterKey = $generateNewKey ? $this->encryptionManager->createEncryptionKey() : null;
        $encryptedEntities = $this->encryptionKeyRepository->findAll();

        foreach ($encryptedEntities as $encryptedEntity) {
            $entityKey = $this->encryptionManager->decrypt($encryptedEntity->getKey(), $dbKey);
            $fields = $this->encryptedFieldsRepository->getFields($encryptedEntity->getEntityClass());
            $entity = $this->em->getRepository($encryptedEntity->getEntityClass())->find($encryptedEntity->getEntityId());
            $newRecordKey = $this->encryptionManager->createEncryptionKey();
            foreach ($fields as $field => $options) {
                if (isset($options['key'])) {
                    $options['key'] = $this->parameterBag->resolveValue($options['key']);
                }
                $key = $options['key'] ?? $entityKey;
                $useMasterKey = $options['useMasterKey'] ?? false;
                $elements = $options['elements'] ?? null;
                $fieldValue = $entity->{'get' . $field}();
                if ($fieldValue === null) {
                    continue;
                }
                if (is_array($fieldValue) && $elements !== null) {
                    foreach ($elements as $element) {
                        $value = $fieldValue[$element] ?? null;
                        if ($value === null) {
                            continue;
                        }
                        if ($useMasterKey) {
                            $fieldValue[$element] = $this->encryptionManager->decrypt($value, $dbKey);
                        } else {
                            $fieldValue[$element] = $this->encryptionManager->decrypt($value, $key);
                        }
                        $fieldValue[$element] = $this->encryptionManager->encrypt($fieldValue[$element], $newRecordKey);
                    }
                    $entity->{'set' . $field}($fieldValue);
                    continue;
                }
                if ($useMasterKey) {
                    $fieldValue = $this->encryptionManager->decrypt($fieldValue, $dbKey);
                } else {
                    $fieldValue = $this->encryptionManager->decrypt($fieldValue, $key);
                }
                $fieldValue = $this->encryptionManager->encrypt($fieldValue, $newRecordKey);
                $entity->{'set' . $field}($fieldValue);
            }
            if ($newMasterKey) {
                $encryptedEntity->setKey($this->encryptionManager->encrypt($newRecordKey, $newMasterKey));
            } else {
                $encryptedEntity->setKey($this->encryptionManager->encryptWithMasterKey($newRecordKey));
            }
            $this->em->flush();
        }
        return $newMasterKey;
    }
}
