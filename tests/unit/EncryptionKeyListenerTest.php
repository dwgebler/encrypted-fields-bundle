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

    public function testPrePersistSetsKeyAndEncryptsWithMasterKey(): void
    {
        $encryptionKey = new EncryptionKey();
        $this->encryptionManager->expects($this->once())
            ->method('createEncryptionKey')
            ->willReturn('generated-key');
        $this->encryptionManager->expects($this->once())
            ->method('encryptWithMasterKey')
            ->with('generated-key')
            ->willReturn('encrypted-key');

        $this->listener->prePersist($encryptionKey);

        $this->assertEquals('encrypted-key', $encryptionKey->getKey());
        $this->assertTrue($encryptionKey->isMasterEncrypted());
    }

    public function testPreUpdateSetsKeyAndEncryptsWithMasterKey(): void
    {
        $encryptionKey = new EncryptionKey();
        $this->encryptionManager->expects($this->once())
            ->method('createEncryptionKey')
            ->willReturn('generated-key');
        $this->encryptionManager->expects($this->once())
            ->method('encryptWithMasterKey')
            ->with('generated-key')
            ->willReturn('encrypted-key');

        $this->listener->preUpdate($encryptionKey);

        $this->assertEquals('encrypted-key', $encryptionKey->getKey());
        $this->assertTrue($encryptionKey->isMasterEncrypted());
    }

    public function testPostLoadDecryptsKeyWithMasterKey(): void
    {
        $encryptionKey = new EncryptionKey();
        $encryptionKey->setKey('encrypted-key');
        $encryptionKey->setMasterEncrypted(true);

        $this->encryptionManager->expects($this->once())
            ->method('decryptWithMasterKey')
            ->with('encrypted-key')
            ->willReturn('decrypted-key');

        $this->listener->postLoad($encryptionKey);

        $this->assertEquals('decrypted-key', $encryptionKey->getKey());
        $this->assertFalse($encryptionKey->isMasterEncrypted());
    }

    public function testPostLoadDoesNothingIfNotMasterEncrypted(): void
    {
        $encryptionKey = new EncryptionKey();
        $encryptionKey->setKey('plain-key');
        $encryptionKey->setMasterEncrypted(false);

        $this->encryptionManager->expects($this->never())
            ->method('decryptWithMasterKey');

        $this->listener->postLoad($encryptionKey);

        $this->assertEquals('plain-key', $encryptionKey->getKey());
        $this->assertFalse($encryptionKey->isMasterEncrypted());
    }
}
