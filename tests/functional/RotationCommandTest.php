<?php

namespace Gebler\EncryptedFieldsBundle\Tests\functional;

use Gebler\EncryptedFieldsBundle\Command\RotateEncryptionKeyCommand;
use Gebler\EncryptedFieldsBundle\Doctrine\EncryptedFieldsListener;
use Gebler\EncryptedFieldsBundle\Doctrine\EncryptionKeyListener;
use Gebler\EncryptedFieldsBundle\Entity\EncryptionKey;
use Gebler\EncryptedFieldsBundle\Service\EncryptionManager;
use Gebler\EncryptedFieldsBundle\Tests\functional\Fixtures\UserEntity;
use Doctrine\ORM\Events;
use Symfony\Component\Console\Tester\CommandTester;

class RotationCommandTest extends FunctionalTestCase
{
    public function testRotateWithGenerateNewKeyPreservesAllFieldFlavours(): void
    {
        $u = new UserEntity();
        $u->setUsername('alice');
        $u->setEmail('alice@example.com');
        $u->setMasterEncryptedNote('top secret');
        $u->setCustomKeyNote('custom secret');
        $u->setMetadata(['secret' => 'shhh', 'token' => 't', 'plain' => 'p']);
        $this->em->persist($u);
        $this->em->flush();
        $id = $u->getId();
        $this->em->clear();

        $command = new RotateEncryptionKeyCommand(
            $this->encryptionManager,
            $this->keyRepo,
            $this->fieldsRepository,
            $this->em,
            $this->parameterBag,
            $this->masterKey,
            $this->listener,
            $this->keyListener,
        );

        $tester = new CommandTester($command);
        $tester->execute(['--generate-new-key' => true]);
        $tester->assertCommandIsSuccessful();
        $output = $tester->getDisplay();
        $this->assertMatchesRegularExpression('/Save the new key:[\s]+[0-9a-f]{64}/s', $output);

        preg_match('/Save the new key:[\s]+([0-9a-f]{64})/s', $output, $m);
        $newMaster = $m[1];

        // Replace listeners with new-master versions so the reload decrypts correctly.
        $newManager = new EncryptionManager($newMaster, 'aes-256-gcm');
        $newFieldsListener = new EncryptedFieldsListener(
            $this->fieldsRepository,
            $this->parameterBag,
            $this->em,
            $newManager,
            $this->keyRepo,
        );
        $newKeyListener = new EncryptionKeyListener($newManager);

        $eventManager = $this->em->getEventManager();
        $eventManager->removeEventListener([Events::prePersist, Events::postPersist], $this->listener);
        $eventManager->removeEventListener([Events::preUpdate, Events::postUpdate], $this->listener);
        $eventManager->removeEventListener([Events::postLoad], $this->listener);
        $eventManager->addEventListener([Events::prePersist, Events::postPersist], $newFieldsListener);
        $eventManager->addEventListener([Events::preUpdate, Events::postUpdate], $newFieldsListener);
        $eventManager->addEventListener([Events::postLoad], $newFieldsListener);

        $keyMeta = $this->em->getClassMetadata(EncryptionKey::class);
        $keyMeta->entityListeners = [];
        $keyMeta->addEntityListener('prePersist', EncryptionKeyListener::class, 'prePersist');
        $keyMeta->addEntityListener('preUpdate', EncryptionKeyListener::class, 'preUpdate');
        $keyMeta->addEntityListener('postLoad', EncryptionKeyListener::class, 'postLoad');
        $resolver = $this->em->getConfiguration()->getEntityListenerResolver();
        $resolver->register($newKeyListener);

        $this->em->clear();
        $reloaded = $this->em->find(UserEntity::class, $id);
        $this->assertSame('alice@example.com', $reloaded->getEmail());
        $this->assertSame('top secret', $reloaded->getMasterEncryptedNote());
        $this->assertSame('custom secret', $reloaded->getCustomKeyNote());
        $this->assertSame('shhh', $reloaded->getMetadata()['secret']);
    }

    public function testRotateSkipsOrphanEncryptionKeyRow(): void
    {
        $orphan = new EncryptionKey();
        $orphan->setEntityClass(UserEntity::class);
        $orphan->setEntityId('999999');
        $orphan->setKey($this->encryptionManager->createEncryptionKey());
        $orphan->setMasterEncrypted(false);
        $this->em->persist($orphan);
        $this->em->flush();
        $this->em->clear();

        $command = new RotateEncryptionKeyCommand(
            $this->encryptionManager,
            $this->keyRepo,
            $this->fieldsRepository,
            $this->em,
            $this->parameterBag,
            $this->masterKey,
            $this->listener,
            $this->keyListener,
        );
        $tester = new CommandTester($command);
        $tester->execute(['--generate-new-key' => true]);
        $tester->assertCommandIsSuccessful();
    }
}
