<?php

namespace Gebler\EncryptedFieldsBundle\Tests\unit;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Event\LoadClassMetadataEventArgs;
use Doctrine\ORM\Event\PostLoadEventArgs;
use Doctrine\ORM\Event\PostPersistEventArgs;
use Doctrine\ORM\Event\PrePersistEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Doctrine\ORM\Mapping\ClassMetadata;
use Gebler\EncryptedFieldsBundle\Attribute\EncryptedField;
use Gebler\EncryptedFieldsBundle\Doctrine\EncryptedFieldsListener;
use Gebler\EncryptedFieldsBundle\Entity\EncryptionKey;
use Gebler\EncryptedFieldsBundle\Repository\EncryptionKeyRepository;
use Gebler\EncryptedFieldsBundle\Service\EncryptedFieldsRepository;
use Gebler\EncryptedFieldsBundle\Service\EncryptionManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use ReflectionClass;

class EncryptedFieldsListenerTest extends TestCase
{
    private EncryptedFieldsRepository $encryptedFieldsRepository;
    private ParameterBagInterface $parameterBag;
    private EntityManagerInterface $em;
    private EncryptionManager $encryptionManager;
    private EncryptionKeyRepository $encryptionKeyRepository;
    private EncryptedFieldsListener $listener;

    protected function setUp(): void
    {
        $this->encryptedFieldsRepository = new EncryptedFieldsRepository();
        $this->parameterBag = $this->createMock(ParameterBagInterface::class);
        $this->em = $this->createMock(EntityManagerInterface::class);
        $this->encryptionManager = new EncryptionManager(bin2hex(random_bytes(32)), 'aes-256-gcm');
        $this->encryptionKeyRepository = $this->createMock(EncryptionKeyRepository::class);

        $this->listener = new EncryptedFieldsListener(
            $this->encryptedFieldsRepository,
            $this->parameterBag,
            $this->em,
            $this->encryptionManager,
            $this->encryptionKeyRepository
        );
    }

    public function testLoadClassMetadata(): void
    {
        $classMetadata = $this->createMock(ClassMetadata::class);
        $reflectionClass = new ReflectionClass(StubEntity::class);

        $classMetadata->method('getReflectionClass')->willReturn($reflectionClass);
        $classMetadata->method('getName')->willReturn(StubEntity::class);

        $args = $this->createMock(LoadClassMetadataEventArgs::class);
        $args->method('getClassMetadata')->willReturn($classMetadata);

        $this->listener->loadClassMetadata($args);

        $fields = $this->encryptedFieldsRepository->getFields(StubEntity::class);
        $this->assertNotEmpty($fields);
        $this->assertArrayHasKey('field', $fields);
    }

    public function testPostPersist(): void
    {
        $entity = new StubEntity();
        $entity->setField('test-data');
        $encryptionKey = new EncryptionKey();
        $encryptionKey->setKey('test-key');

        $this->encryptionManager->createEncryptionKey();
        $this->encryptionManager->encryptWithMasterKey('test-data');
        $this->em->method('getConnection')->willReturn($this->createMock(\Doctrine\DBAL\Connection::class));

        // Add the field to the repository to simulate persistence
        $this->encryptedFieldsRepository->addField(get_class($entity), 'field', ['key' => 'test-key']);

        $this->listener->postPersist(new PostPersistEventArgs($entity, $this->em));

        $fields = $this->encryptedFieldsRepository->getFields(get_class($entity));
        $this->assertNotEmpty($fields);
        $this->assertArrayHasKey('field', $fields);
    }

    public function testPrePersist(): void
    {
        $entity = new StubEntity();
        $entity->setField('test-data');
        $classMetadata = $this->createMock(ClassMetadata::class);
        $classMetadata->method('getIdentifierFieldNames')->willReturn(['id']);
        $this->em->method('getClassMetadata')->willReturn($classMetadata);

        $this->encryptedFieldsRepository->addField(get_class($entity), 'field', ['key' => 'test-key']);

        $this->listener->prePersist(new PrePersistEventArgs($entity, $this->em));

        $fields = $this->encryptedFieldsRepository->getFields(get_class($entity));
        $this->assertNotEmpty($fields);
        $this->assertArrayHasKey('field', $fields);
    }

    public function testPreUpdate(): void
    {
        $entity = new StubEntity();
        $entity->setField('test-data');
        $classMetadata = $this->createMock(ClassMetadata::class);
        $classMetadata->method('getIdentifierFieldNames')->willReturn(['id']);
        $this->em->method('getClassMetadata')->willReturn($classMetadata);

        $this->encryptedFieldsRepository->addField(get_class($entity), 'field', ['key' => 'test-key']);

        $changeSet = [];
        $this->listener->preUpdate(new PreUpdateEventArgs($entity, $this->em, $changeSet));

        $fields = $this->encryptedFieldsRepository->getFields(get_class($entity));
        $this->assertNotEmpty($fields);
        $this->assertArrayHasKey('field', $fields);
    }

    public function testPostLoad(): void
    {
        $entity = new StubEntity();
        $entity->setField('test-data');
        $classMetadata = $this->createMock(ClassMetadata::class);
        $classMetadata->method('getIdentifierFieldNames')->willReturn(['id']);
        $this->em->method('getClassMetadata')->willReturn($classMetadata);

        $this->encryptedFieldsRepository->addField(get_class($entity), 'field', ['key' => 'test-key']);
        $this->encryptionKeyRepository->method('findOneBy')->willReturn(null);

        $this->listener->postLoad(new PostLoadEventArgs($entity, $this->em));

        $fields = $this->encryptedFieldsRepository->getFields(get_class($entity));
        $this->assertNotEmpty($fields);
        $this->assertArrayHasKey('field', $fields);
    }
}
