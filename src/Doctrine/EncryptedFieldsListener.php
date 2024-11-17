<?php

namespace Gebler\EncryptedFieldsBundle\Doctrine;

use Gebler\EncryptedFieldsBundle\Entity\EncryptionKey;
use Gebler\EncryptedFieldsBundle\Repository\EncryptionKeyRepository;
use Gebler\EncryptedFieldsBundle\Service\EncryptedFieldsRepository;
use Gebler\EncryptedFieldsBundle\Service\EncryptionManager;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Event\PostLoadEventArgs;
use Doctrine\ORM\Event\PostPersistEventArgs;
use Doctrine\ORM\Event\PrePersistEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

class EncryptedFieldsListener
{
    private array $encryptionKeysToLink = [];

    public function __construct(
        private EncryptedFieldsRepository $encryptedFieldsRepository,
        private ParameterBagInterface $parameterBag,
        private EntityManagerInterface $em,
        private EncryptionManager $encryptionManager,
        private EncryptionKeyRepository $encryptionKeyRepository,
    ) {
    }

    public function postPersist(PostPersistEventArgs $args): void
    {
        $entity = $args->getObject();
        if (isset($this->encryptionKeysToLink[spl_object_hash($entity)])) {
            /** @var EncryptionKey $encryptionKey */
            $encryptionKey = $this->encryptionKeysToLink[spl_object_hash($entity)];
            if ($encryptionKey->getKey() === null) {
                $encryptionKey->setKey($this->encryptionManager->createEncryptionKey());
            }
            $encryptionKey->setKey($this->encryptionManager->encryptWithMasterKey($encryptionKey->getKey()));
            $encryptionKey->setEntityId($entity->getId());
            $connection = $this->em->getConnection();
            $nextId = $connection->fetchOne('SELECT nextval(\'encryption_key_id_seq\')');
            $connection->insert('encryption_key', [
                'id' => $nextId,
                'entity_id' => $encryptionKey->getEntityId(),
                'entity_class' => $encryptionKey->getEntityClass(),
                'key' => $encryptionKey->getKey(),
            ]);
            unset($this->encryptionKeysToLink[spl_object_hash($entity)]);
        }
    }

    public function prePersist(PrePersistEventArgs $args): void
    {
        $entity = $args->getObject();
        $this->encryptFields($entity);
    }

    public function preUpdate(PreUpdateEventArgs $args): void
    {
        $entity = $args->getObject();
        $this->encryptFields($entity);
    }

    public function postLoad(PostLoadEventArgs $args): void
    {
        $entity = $args->getObject();
        $fields = $this->encryptedFieldsRepository->getFields(get_class($entity));

        if (empty($fields)) {
            return;
        }

        $classMetadata = $this->em->getClassMetadata(get_class($entity));
        $identifierField = $classMetadata->getIdentifierFieldNames()[0];
        $entityId = $classMetadata->getFieldValue($entity, $identifierField);

        $encryptionKey = $this->encryptionKeyRepository->findOneBy([
            'entityId' => $entityId,
            'entityClass' => get_class($entity),
        ]);

        if (!$encryptionKey) {
            return;
        }

        foreach ($fields as $field => $options) {
            if (isset($options['key'])) {
                $options['key'] = $this->parameterBag->resolveValue($options['key']);
            }
            $key = $options['key'] ?? null;
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
                    } elseif ($key) {
                        $fieldValue[$element] = $this->encryptionManager->decrypt($value, $key);
                    } else {
                        $fieldValue[$element] = $this->encryptionManager->decrypt($value, $encryptionKey->getKey());
                    }
                }
                $entity->{'set' . $field}($fieldValue);
                continue;
            }
            if ($useMasterKey) {
                $fieldValue = $this->encryptionManager->decryptWithMasterKey($fieldValue);
            } elseif ($key) {
                $fieldValue = $this->encryptionManager->decrypt($fieldValue, $key);
            } else {
                $fieldValue = $this->encryptionManager->decrypt($fieldValue, $encryptionKey->getKey());
            }
            $entity->{'set' . $field}($fieldValue);
        }
    }

    private function encryptFields(object $entity): void
    {
        $fields = $this->encryptedFieldsRepository->getFields(get_class($entity));

        if (empty($fields)) {
            return;
        }

        $classMetadata = $this->em->getClassMetadata(get_class($entity));
        $identifierField = $classMetadata->getIdentifierFieldNames()[0];
        $entityId = $classMetadata->getFieldValue($entity, $identifierField);

        $encryptionKey = $entityId ? $this->encryptionKeyRepository->findOneBy([
            'entityId' => $entityId,
            'entityClass' => get_class($entity),
        ]) : null;

        foreach ($fields as $field => $options) {
            if (isset($options['key'])) {
                $options['key'] = $this->parameterBag->resolveValue($options['key']);
            }
            $key = $options['key'] ?? null;
            $useMasterKey = $options['useMasterKey'] ?? false;
            $elements = $options['elements'] ?? null;
            $fieldValue = $entity->{'get' . $field}();
            if ($fieldValue === null) {
                continue;
            }

            if (!$key && !$encryptionKey) {
                $encryptionKey = new EncryptionKey();
                $encryptionKey->setEntityClass(get_class($entity));
                $encryptionKey->setKey($this->encryptionManager->createEncryptionKey());
                if ($entityId) {
                    $encryptionKey->setEntityId($entityId);
                    $this->em->persist($encryptionKey);
                } else {
                    $this->encryptionKeysToLink[spl_object_hash($entity)] = $encryptionKey;
                }
            }

            if (is_array($fieldValue) && $elements !== null) {
                foreach ($elements as $element) {
                    $value = $fieldValue[$element] ?? null;
                    if ($value === null) {
                        continue;
                    }
                    if ($useMasterKey) {
                        $fieldValue[$element] = $this->encryptionManager->encryptWithMasterKey($value);
                    } elseif ($key) {
                        $fieldValue[$element] = $this->encryptionManager->encrypt($value, $key);
                    } else {
                        $fieldValue[$element] = $this->encryptionManager->encrypt($value, $encryptionKey->getKey());
                    }
                }
                $entity->{'set' . $field}($fieldValue);
                continue;
            }
            if ($useMasterKey) {
                $fieldValue = $this->encryptionManager->encryptWithMasterKey($fieldValue);
            } elseif ($key) {
                $fieldValue = $this->encryptionManager->encrypt($fieldValue, $key);
            } else {
                $fieldValue = $this->encryptionManager->encrypt($fieldValue, $encryptionKey->getKey());
            }
            $entity->{'set' . $field}($fieldValue);
        }
    }
}
