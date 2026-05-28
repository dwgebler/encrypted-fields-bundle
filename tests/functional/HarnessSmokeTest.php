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

    public function testEncryptionKeyAcceptsStringEntityId(): void
    {
        $key = new \Gebler\EncryptedFieldsBundle\Entity\EncryptionKey();
        $key->setEntityClass('Some\\Class');
        $key->setEntityId('abc-uuid-or-whatever');
        $key->setKey(bin2hex(random_bytes(32)));
        $key->setMasterEncrypted(false);

        $this->em->persist($key);
        $this->em->flush();
        $this->em->clear();

        $loaded = $this->keyRepo->findOneByEntity('Some\\Class', 'abc-uuid-or-whatever');
        $this->assertNotNull($loaded);
        $this->assertSame('abc-uuid-or-whatever', $loaded->getEntityId());
    }
}
