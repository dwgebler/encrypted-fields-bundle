<?php

namespace Gebler\EncryptedFieldsBundle\Tests\functional;

use Gebler\EncryptedFieldsBundle\Tests\functional\Fixtures\CompositeKeyEntity;
use Gebler\EncryptedFieldsBundle\Tests\functional\Fixtures\UuidKeyEntity;

class CompositeAndUuidIdentifierTest extends FunctionalTestCase
{
    public function testCompositeKeyRoundTrip(): void
    {
        $e = new CompositeKeyEntity(1, 'acct-A');
        $e->setSecret('hello');
        $this->em->persist($e);
        $this->em->flush();
        $this->em->clear();

        $reloaded = $this->em->find(CompositeKeyEntity::class, ['tenantId' => 1, 'accountCode' => 'acct-A']);
        $this->assertSame('hello', $reloaded->getSecret());
    }

    public function testUuidKeyRoundTrip(): void
    {
        $e = new UuidKeyEntity();
        $id = $e->getId();
        $e->setSecret('hello');
        $this->em->persist($e);
        $this->em->flush();
        $this->em->clear();

        $reloaded = $this->em->find(UuidKeyEntity::class, $id);
        $this->assertSame('hello', $reloaded->getSecret());
    }
}
