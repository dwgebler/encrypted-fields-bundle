<?php

namespace Gebler\EncryptedFieldsBundle\Tests\functional;

use Gebler\EncryptedFieldsBundle\Entity\EncryptionKey;
use Gebler\EncryptedFieldsBundle\Tests\functional\Fixtures\UserEntity;

class HarnessSmokeTest extends FunctionalTestCase
{
    public function testSchemaCreatedAndEntitiesPersistable(): void
    {
        $u = new UserEntity();
        $u->setUsername('alice');
        $u->setEmail('alice@example.com');
        $u->setMasterEncryptedNote('m');
        $u->setCustomKeyNote('c');
        $u->setMetadata(['secret' => 's', 'token' => 't', 'plain' => 'p']);

        $this->em->persist($u);
        $this->em->flush();
        $this->assertNotNull($u->getId());

        $keys = $this->em->getRepository(EncryptionKey::class)->findAll();
        $this->assertCount(1, $keys);
    }
}
