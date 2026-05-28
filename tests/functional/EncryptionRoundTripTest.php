<?php

namespace Gebler\EncryptedFieldsBundle\Tests\functional;

use Gebler\EncryptedFieldsBundle\Tests\functional\Fixtures\UserEntity;

class EncryptionRoundTripTest extends FunctionalTestCase
{
    public function testPersistAndReloadRoundTripsAllFieldFlavours(): void
    {
        $u = new UserEntity();
        $u->setUsername('alice');
        $u->setEmail('alice@example.com');
        $u->setMasterEncryptedNote('top secret');
        $u->setCustomKeyNote('custom secret');
        $u->setMetadata(['secret' => 'shhh', 'token' => 'abc', 'plain' => 'public']);

        $this->em->persist($u);
        $this->em->flush();
        $id = $u->getId();
        $this->em->clear();

        $reloaded = $this->em->find(UserEntity::class, $id);
        $this->assertSame('alice@example.com', $reloaded->getEmail());
        $this->assertSame('top secret', $reloaded->getMasterEncryptedNote());
        $this->assertSame('custom secret', $reloaded->getCustomKeyNote());
        $this->assertSame('shhh', $reloaded->getMetadata()['secret']);
        $this->assertSame('abc', $reloaded->getMetadata()['token']);
        $this->assertSame('public', $reloaded->getMetadata()['plain']);
    }

    public function testRawDbValueIsCiphertextNotPlain(): void
    {
        $u = new UserEntity();
        $u->setUsername('alice');
        $u->setEmail('alice@example.com');
        $u->setMasterEncryptedNote('m');
        $u->setCustomKeyNote('c');
        $u->setMetadata(['secret' => 'shhh', 'token' => 't', 'plain' => 'p']);
        $this->em->persist($u);
        $this->em->flush();
        $id = $u->getId();

        $row = $this->em->getConnection()->fetchAssociative('SELECT email FROM fixture_user WHERE id = ?', [$id]);
        $this->assertNotSame('alice@example.com', $row['email']);
        $this->assertGreaterThan(28, strlen(base64_decode($row['email'])));
    }
}
