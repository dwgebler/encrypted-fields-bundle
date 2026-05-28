<?php

namespace Gebler\EncryptedFieldsBundle\Doctrine;

use Doctrine\Common\Util\ClassUtils;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Event\LoadClassMetadataEventArgs;
use Doctrine\ORM\Event\PostLoadEventArgs;
use Doctrine\ORM\Event\PostPersistEventArgs;
use Doctrine\ORM\Event\PostUpdateEventArgs;
use Doctrine\ORM\Event\PrePersistEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Gebler\EncryptedFieldsBundle\Attribute\EncryptedField;
use Gebler\EncryptedFieldsBundle\Entity\EncryptionKey;
use Gebler\EncryptedFieldsBundle\Repository\EncryptionKeyRepository;
use Gebler\EncryptedFieldsBundle\Service\EncryptedFieldsRepository;
use Gebler\EncryptedFieldsBundle\Service\EncryptionManagerInterface;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;

/**
 * Bridges Doctrine lifecycle events to symmetric encryption of `#[EncryptedField]`
 * properties. Two crypto paths live here:
 *
 * - Listener path: `postLoad` decrypts ciphertext into the entity properties and
 *   patches `UnitOfWork::originalEntityData` with the plain values so subsequent
 *   change-set computation compares plain-vs-plain. `preUpdate` encrypts changed
 *   fields back to ciphertext via `PreUpdateEventArgs::setNewValue` — never via
 *   the entity setter, since the UPDATE SQL is built from the change set, not
 *   the entity. Unchanged fields are skipped, so no re-encryption occurs.
 * - Clone-with-plain-key path: when a new EncryptionKey is persisted, the
 *   companion `EncryptionKeyListener` master-encrypts it in place during flush.
 *   `persistAndCloneWithPlainKey` captures the plain key before flush so the
 *   caller can continue to encrypt/decrypt this entity's fields with it.
 *
 * The rotation command (`RotateEncryptionKeyCommand`) uses a third path that
 * disables both listeners via `setEnabled(false)` and handles master encryption
 * manually. The toggle exists to keep the three paths from interfering.
 */
class EncryptedFieldsListener
{
    private bool $enabled = true;
    /** @var \WeakMap<object, EncryptionKey> */
    private \WeakMap $encryptionKeysToLink;

    public function __construct(
        private readonly EncryptedFieldsRepository $encryptedFieldsRepository,
        private readonly ParameterBagInterface $parameterBag,
        private readonly EntityManagerInterface $em,
        private readonly EncryptionManagerInterface $encryptionManager,
        private readonly EncryptionKeyRepository $encryptionKeyRepository,
    ) {
        $this->encryptionKeysToLink = new \WeakMap();
    }

    public function setEnabled(bool $enabled): void
    {
        $this->enabled = $enabled;
    }

    public function loadClassMetadata(LoadClassMetadataEventArgs $args): void
    {
        $classMetadata = $args->getClassMetadata();
        $reflectionClass = $classMetadata->getReflectionClass();
        foreach ($reflectionClass->getProperties() as $property) {
            $attributes = $property->getAttributes(EncryptedField::class);
            if ($attributes === []) {
                continue;
            }
            $attribute = $attributes[0]->newInstance();
            $this->encryptedFieldsRepository->addField(
                $classMetadata->getName(),
                $property->getName(),
                [
                    'elements'     => $attribute->elements,
                    'useMasterKey' => $attribute->useMasterKey,
                    'key'          => $attribute->key,
                ]
            );
        }
    }

    public function prePersist(PrePersistEventArgs $args): void
    {
        if (!$this->enabled) {
            return;
        }
        $entity = $args->getObject();
        $fields = $this->fieldsFor($entity);
        if ($fields === []) {
            return;
        }

        $encryptionKey = $this->ensureEncryptionKeyForInsert($entity);
        foreach ($fields as $field => $options) {
            $plain = $this->readField($entity, $field);
            if ($plain === null) {
                continue;
            }
            $this->writeField($entity, $field, $this->encryptValue($plain, $options, $encryptionKey));
        }
    }

    public function postPersist(PostPersistEventArgs $args): void
    {
        if (!$this->enabled) {
            return;
        }
        $entity = $args->getObject();
        $fields = $this->fieldsFor($entity);
        if ($fields === []) {
            return;
        }

        if (isset($this->encryptionKeysToLink[$entity])) {
            $encryptionKey = $this->encryptionKeysToLink[$entity];
            $encryptionKey->setEntityId($this->identifierFor($entity) ?? '');
            $decryptionKey = $this->persistAndCloneWithPlainKey($encryptionKey);
            unset($this->encryptionKeysToLink[$entity]);
        } else {
            $decryptionKey = $this->loadEncryptionKey($entity);
        }

        if ($decryptionKey === null) {
            $this->snapshotPlainValues($entity, $fields);
            return;
        }

        foreach ($fields as $field => $options) {
            $cipher = $this->readField($entity, $field);
            if ($cipher === null) {
                continue;
            }
            $plain = $this->decryptValue($cipher, $options, $decryptionKey);
            $this->writeField($entity, $field, $plain);
        }
        $this->snapshotPlainValues($entity, $fields);
    }

    public function preUpdate(PreUpdateEventArgs $args): void
    {
        if (!$this->enabled) {
            return;
        }
        $entity = $args->getObject();
        $fields = $this->fieldsFor($entity);
        if ($fields === []) {
            return;
        }

        $encryptionKey = $this->loadEncryptionKey($entity);
        if ($encryptionKey === null) {
            // Edge case: an existing entity has no EncryptionKey row (e.g. an
            // #[EncryptedField] annotation was added after rows existed).
            // Build one and flush it now — postPersist won't fire on update.
            $newKey = new EncryptionKey();
            $newKey->setEntityClass(ClassUtils::getClass($entity));
            $newKey->setEntityId($this->identifierFor($entity) ?? '');
            $newKey->setMasterEncrypted(false);
            $newKey->setKey($this->encryptionManager->createEncryptionKey());
            $encryptionKey = $this->persistAndCloneWithPlainKey($newKey);
        }

        foreach ($fields as $field => $options) {
            if (!$args->hasChangedField($field)) {
                continue;
            }
            $newValue = $args->getNewValue($field);
            if ($newValue === null) {
                continue;
            }
            $ciphertext = $this->encryptValue($newValue, $options, $encryptionKey);
            $args->setNewValue($field, $ciphertext);
            $this->em->getUnitOfWork()->setOriginalEntityProperty(
                spl_object_id($entity), $field, $newValue
            );
        }
    }

    public function postUpdate(PostUpdateEventArgs $args): void
    {
        // Entity properties stayed plain throughout the update — we used
        // PreUpdateEventArgs::setNewValue to feed ciphertext into the change
        // set without touching the entity. Nothing to undo.
    }

    public function postLoad(PostLoadEventArgs $args): void
    {
        if (!$this->enabled) {
            return;
        }
        $entity = $args->getObject();
        $fields = $this->fieldsFor($entity);
        if ($fields === []) {
            return;
        }
        $encryptionKey = $this->loadEncryptionKey($entity);
        if ($encryptionKey === null) {
            $this->snapshotPlainValues($entity, $fields);
            return;
        }

        foreach ($fields as $field => $options) {
            $cipher = $this->readField($entity, $field);
            if ($cipher === null) {
                continue;
            }
            $this->writeField($entity, $field, $this->decryptValue($cipher, $options, $encryptionKey));
        }
        $this->snapshotPlainValues($entity, $fields);
    }

    // ---------- helpers ----------

    /** @return array<string, array<string, mixed>> */
    private function fieldsFor(object $entity): array
    {
        return $this->encryptedFieldsRepository->getFields(ClassUtils::getClass($entity));
    }

    private function identifierFor(object $entity): ?string
    {
        $meta = $this->em->getClassMetadata(ClassUtils::getClass($entity));
        $ids = $meta->getIdentifierValues($entity);
        if ($ids === [] || in_array(null, $ids, true)) {
            return null;
        }
        ksort($ids);
        return implode("\x1f", array_map(static fn($v): string => (string) $v, $ids));
    }

    private function loadEncryptionKey(object $entity): ?EncryptionKey
    {
        $id = $this->identifierFor($entity);
        if ($id === null) {
            return null;
        }
        return $this->encryptionKeyRepository->findOneByEntity(ClassUtils::getClass($entity), $id);
    }

    private function ensureEncryptionKeyForInsert(object $entity): EncryptionKey
    {
        if (isset($this->encryptionKeysToLink[$entity])) {
            return $this->encryptionKeysToLink[$entity];
        }
        $encryptionKey = new EncryptionKey();
        $encryptionKey->setEntityClass(ClassUtils::getClass($entity));
        $encryptionKey->setMasterEncrypted(false);
        $encryptionKey->setKey($this->encryptionManager->createEncryptionKey());
        $this->encryptionKeysToLink[$entity] = $encryptionKey;
        return $encryptionKey;
    }

    /**
     * Persist an EncryptionKey and return a transient clone holding the plain
     * hex key. EncryptionKeyListener::prePersist mutates the persisted object
     * in place to its master-encrypted form during flush, so callers that need
     * to encrypt or decrypt with this key after persistence use the clone.
     */
    private function persistAndCloneWithPlainKey(EncryptionKey $encryptionKey): EncryptionKey
    {
        $plainKey = $encryptionKey->getKey();
        $this->em->persist($encryptionKey);
        $this->em->flush($encryptionKey);

        $clone = new EncryptionKey();
        $clone->setEntityClass($encryptionKey->getEntityClass());
        $clone->setEntityId($encryptionKey->getEntityId());
        $clone->setMasterEncrypted(false);
        $clone->setKey($plainKey);
        return $clone;
    }

    /** @param array<string, array<string, mixed>> $fields */
    private function snapshotPlainValues(object $entity, array $fields): void
    {
        $uow = $this->em->getUnitOfWork();
        $oid = spl_object_id($entity);
        foreach ($fields as $field => $_options) {
            $uow->setOriginalEntityProperty($oid, $field, $this->readField($entity, $field));
        }
    }

    private function readField(object $entity, string $field): mixed
    {
        $getter = 'get' . $field;
        return $entity->{$getter}();
    }

    private function writeField(object $entity, string $field, mixed $value): void
    {
        $setter = 'set' . $field;
        $entity->{$setter}($value);
    }

    /** @param array<string, mixed> $options */
    private function encryptValue(mixed $value, array $options, EncryptionKey $encryptionKey): mixed
    {
        $elements = $options['elements'] ?? null;
        if (is_array($value) && $elements !== null) {
            foreach ($elements as $element) {
                if (!array_key_exists($element, $value) || $value[$element] === null) {
                    continue;
                }
                $value[$element] = $this->encryptScalar((string) $value[$element], $options, $encryptionKey);
            }
            return $value;
        }
        return $this->encryptScalar((string) $value, $options, $encryptionKey);
    }

    /** @param array<string, mixed> $options */
    private function decryptValue(mixed $value, array $options, EncryptionKey $encryptionKey): mixed
    {
        $elements = $options['elements'] ?? null;
        if (is_array($value) && $elements !== null) {
            foreach ($elements as $element) {
                if (!array_key_exists($element, $value) || $value[$element] === null) {
                    continue;
                }
                $value[$element] = $this->decryptScalar((string) $value[$element], $options, $encryptionKey);
            }
            return $value;
        }
        return $this->decryptScalar((string) $value, $options, $encryptionKey);
    }

    /** @param array<string, mixed> $options */
    private function encryptScalar(string $value, array $options, EncryptionKey $encryptionKey): string
    {
        if ($options['useMasterKey'] ?? false) {
            return $this->encryptionManager->encryptWithMasterKey($value);
        }
        if (($options['key'] ?? null) !== null) {
            return $this->encryptionManager->encrypt($value, $this->resolveCustomKey($options['key']));
        }
        return $this->encryptionManager->encrypt($value, $encryptionKey->getKey());
    }

    /** @param array<string, mixed> $options */
    private function decryptScalar(string $value, array $options, EncryptionKey $encryptionKey): string
    {
        if ($options['useMasterKey'] ?? false) {
            return $this->encryptionManager->decryptWithMasterKey($value);
        }
        if (($options['key'] ?? null) !== null) {
            return $this->encryptionManager->decrypt($value, $this->resolveCustomKey($options['key']));
        }
        return $this->encryptionManager->decrypt($value, $encryptionKey->getKey());
    }

    private function resolveCustomKey(string $keyOrParam): string
    {
        return (string) $this->parameterBag->resolveValue($keyOrParam);
    }
}
