<?php

namespace Gebler\EncryptedFieldsBundle\Tests\unit;

use Gebler\EncryptedFieldsBundle\Doctrine\EncryptionKeyListener;
use Gebler\EncryptedFieldsBundle\Entity\EncryptionKey;
use Gebler\EncryptedFieldsBundle\Service\EncryptionManagerInterface;
use PHPUnit\Framework\TestCase;

class EncryptionKeyListenerTest extends TestCase
{
    private EncryptionManagerInterface $encryptionManager;
    private EncryptionKeyListener $listener;

    protected function setUp(): void
    {
        $this->encryptionManager = $this->createMock(EncryptionManagerInterface::class);
        $this->listener = new EncryptionKeyListener($this->encryptionManager);
    }

    public function testPrePersistOnAlreadyMasterEncryptedIsNoop(): void
    {
        $k = new EncryptionKey();
        $k->setKey('already-encrypted');
        $k->setMasterEncrypted(true);
        $this->encryptionManager->expects($this->never())->method('encryptWithMasterKey');
        $this->listener->prePersist($k);
        $this->assertSame('already-encrypted', $k->getKey());
    }

    public function testPrePersistEncryptsPlainKey(): void
    {
        $k = new EncryptionKey();
        $k->setKey('plain');
        $k->setMasterEncrypted(false);
        $this->encryptionManager->expects($this->once())
            ->method('encryptWithMasterKey')->with('plain')->willReturn('enc');
        $this->listener->prePersist($k);
        $this->assertSame('enc', $k->getKey());
        $this->assertTrue($k->isMasterEncrypted());
    }

    public function testPreUpdateOnAlreadyMasterEncryptedIsNoop(): void
    {
        $k = new EncryptionKey();
        $k->setKey('already-encrypted');
        $k->setMasterEncrypted(true);
        $this->encryptionManager->expects($this->never())->method('encryptWithMasterKey');
        $this->listener->preUpdate($k);
        $this->assertSame('already-encrypted', $k->getKey());
    }

    public function testPreUpdateEncryptsPlainKey(): void
    {
        $k = new EncryptionKey();
        $k->setKey('plain');
        $k->setMasterEncrypted(false);
        $this->encryptionManager->expects($this->once())
            ->method('encryptWithMasterKey')->with('plain')->willReturn('enc');
        $this->listener->preUpdate($k);
        $this->assertSame('enc', $k->getKey());
        $this->assertTrue($k->isMasterEncrypted());
    }

    public function testPostLoadDecryptsWhenMasterEncrypted(): void
    {
        $k = new EncryptionKey();
        $k->setKey('enc');
        $k->setMasterEncrypted(true);
        $this->encryptionManager->expects($this->once())
            ->method('decryptWithMasterKey')->with('enc')->willReturn('plain');
        $this->listener->postLoad($k);
        $this->assertSame('plain', $k->getKey());
        $this->assertFalse($k->isMasterEncrypted());
    }

    public function testPostLoadDoesNothingIfNotMasterEncrypted(): void
    {
        $k = new EncryptionKey();
        $k->setKey('plain-key');
        $k->setMasterEncrypted(false);
        $this->encryptionManager->expects($this->never())->method('decryptWithMasterKey');
        $this->listener->postLoad($k);
        $this->assertSame('plain-key', $k->getKey());
        $this->assertFalse($k->isMasterEncrypted());
    }

    public function testSetEnabledFalseSuppressesAllEvents(): void
    {
        $k = new EncryptionKey();
        $k->setKey('plain');
        $k->setMasterEncrypted(false);
        $this->encryptionManager->expects($this->never())->method('encryptWithMasterKey');
        $this->encryptionManager->expects($this->never())->method('decryptWithMasterKey');

        $this->listener->setEnabled(false);
        $this->listener->prePersist($k);
        $this->listener->preUpdate($k);
        $this->listener->postLoad($k);

        $this->assertSame('plain', $k->getKey());
    }
}
