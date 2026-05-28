<?php

namespace Gebler\EncryptedFieldsBundle\Tests\functional;

use Gebler\EncryptedFieldsBundle\Tests\functional\Fixtures\UserEntity;

class PreUpdateChangesetTest extends FunctionalTestCase
{
    public function testUpdatingAnEncryptedFieldStoresCiphertextNotPlain(): void
    {
        $u = new UserEntity();
        $u->setUsername('alice');
        $u->setEmail('alice@example.com');
        $u->setMasterEncryptedNote('m');
        $u->setCustomKeyNote('c');
        $u->setMetadata([]);
        $this->em->persist($u);
        $this->em->flush();
        $id = $u->getId();
        $this->em->clear();

        $reloaded = $this->em->find(UserEntity::class, $id);
        $reloaded->setEmail('bob@example.com');
        $this->em->flush();

        $row = $this->em->getConnection()->fetchAssociative('SELECT email FROM fixture_user WHERE id = ?', [$id]);
        // 1.x writes 'bob@example.com' here. 2.0 must not.
        $this->assertNotSame('bob@example.com', $row['email']);

        $this->em->clear();
        $reloaded2 = $this->em->find(UserEntity::class, $id);
        $this->assertSame('bob@example.com', $reloaded2->getEmail());
    }
}
