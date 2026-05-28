<?php

namespace Gebler\EncryptedFieldsBundle\Tests\functional;

use Gebler\EncryptedFieldsBundle\Tests\functional\Fixtures\UserEntity;

class SkipUnchangedReencryptionTest extends FunctionalTestCase
{
    public function testIdleFlushIssuesNoUpdate(): void
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
        $this->clearSqlLog();
        $this->em->flush();

        $updates = $this->lastSqlMatching('/^UPDATE fixture_user/i');
        $this->assertSame([], $updates, 'No UPDATE expected when nothing changed; got: ' . implode("\n", $updates));
    }

    public function testUpdateOfNonEncryptedColumnDoesNotTouchEncryptedColumns(): void
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
        $reloaded->setUsername('alice2');
        $this->clearSqlLog();
        $this->em->flush();

        $updates = $this->lastSqlMatching('/^UPDATE fixture_user/i');
        $this->assertCount(1, $updates);
        $this->assertStringContainsString('username', $updates[0]);
        $this->assertStringNotContainsString('email', $updates[0]);
        $this->assertStringNotContainsString('master_encrypted_note', $updates[0]);
        $this->assertStringNotContainsString('custom_key_note', $updates[0]);
    }

    public function testCiphertextStableOnIdleReflush(): void
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

        $before = $this->em->getConnection()->fetchOne('SELECT email FROM fixture_user WHERE id = ?', [$id]);
        $this->em->clear();
        $reloaded = $this->em->find(UserEntity::class, $id);
        $this->em->flush();
        $after = $this->em->getConnection()->fetchOne('SELECT email FROM fixture_user WHERE id = ?', [$id]);

        $this->assertSame($before, $after, 'Ciphertext should be byte-identical when plain unchanged');
    }
}
