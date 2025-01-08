<?php

namespace Gebler\EncryptedFieldsBundle\Doctrine;

use Doctrine\Common\Util\ClassUtils;
use Doctrine\ORM\Event\LoadClassMetadataEventArgs;
use Doctrine\ORM\Event\PostUpdateEventArgs;
use Gebler\EncryptedFieldsBundle\Attribute\EncryptedField;
use Gebler\EncryptedFieldsBundle\Entity\EncryptionKey;
use Gebler\EncryptedFieldsBundle\Repository\EncryptionKeyRepository;
use Gebler\EncryptedFieldsBundle\Service\EncryptedFieldsRepository;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Event\PostLoadEventArgs;
use Doctrine\ORM\Event\PostPersistEventArgs;
use Doctrine\ORM\Event\PrePersistEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Gebler\EncryptedFieldsBundle\Service\EncryptionManagerInterface;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

class EncryptedFieldsListener
{
    private array $encryptionKeysToLink = [];

    public function __construct(
        private EncryptedFieldsRepository $encryptedFieldsRepository,
        private ParameterBagInterface $parameterBag,
        private EntityManagerInterface $em,
        private EncryptionManagerInterface $encryptionManager,
        private EncryptionKeyRepository $encryptionKeyRepository,
    ) {
    }

    public function loadClassMetadata(LoadClassMetadataEventArgs $args): void
    {
        $classMetadata = $args->getClassMetadata();
        $reflectionClass = $classMetadata->getReflectionClass();
        foreach ($reflectionClass->getProperties() as $property) {
            $attribute = $property->getAttributes(EncryptedField::class);
            if (empty($attribute)) {
                continue;
            }
            $attribute = $attribute[0]->newInstance();
            $options = [
                'elements' => $attribute->elements,
                'useMasterKey' => $attribute->useMasterKey,
                'key' => $attribute->key,
            ];
            $this->encryptedFieldsRepository->addField($classMetadata->getName(), $property->getName(), $options);
        }
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
            $encryptionKey->setMasterEncrypted(true);
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
            $this->decryptFields($entity, $encryptionKey);
            return;
        }
        $this->decryptFields($entity);
    }

    public function postUpdate(PostUpdateEventArgs $args): void
    {
        $entity = $args->getObject();
        $this->decryptFields($entity);
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
        $this->decryptFields($entity);
    }

    private function decryptFields(object $entity, ?EncryptionKey $encryptionKey = null): void
    {
        $realClass = ClassUtils::getRealClass($entity);
        $fields = $this->encryptedFieldsRepository->getFields($realClass);

        if (empty($fields)) {
            return;
        }

        $classMetadata = $this->em->getClassMetadata($realClass);
        $identifierField = $classMetadata->getIdentifierFieldNames()[0];
        $entityId = $classMetadata->getFieldValue($entity, $identifierField);

        $encryptionKey ??= $this->encryptionKeyRepository->findOneBy([
            'entityId' => $entityId,
            'entityClass' => $realClass,
        ]);

        if (!$encryptionKey) {
            return;
        }

        $this->em->detach($encryptionKey);

        if ($encryptionKey->isMasterEncrypted()) {
            $encryptionKey->setKey($this->encryptionManager->decryptWithMasterKey($encryptionKey->getKey()));
            $encryptionKey->setMasterEncrypted(false);
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
        $realClass = ClassUtils::getRealClass($entity);
        $fields = $this->encryptedFieldsRepository->getFields($realClass);

        if (empty($fields)) {
            return;
        }

        $classMetadata = $this->em->getClassMetadata($realClass);
        $identifierField = $classMetadata->getIdentifierFieldNames()[0];
        $entityId = $classMetadata->getFieldValue($entity, $identifierField);

        $encryptionKey = $entityId ? $this->encryptionKeyRepository->findOneBy([
            'entityId' => $entityId,
            'entityClass' => $realClass,
        ]) : null;

        if ($encryptionKey) {
            $this->em->detach($encryptionKey);
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

            if (!$key && !$encryptionKey) {
                $encryptionKey = new EncryptionKey();
                $encryptionKey->setMasterEncrypted(false);
                $encryptionKey->setEntityClass($realClass);
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
