<?php

namespace Gebler\EncryptedFieldsBundle\Doctrine;

use Gebler\EncryptedFieldsBundle\Entity\EncryptionKey;
use Gebler\EncryptedFieldsBundle\Service\EncryptionManagerInterface;

class EncryptionKeyListener
{
    private bool $enabled = true;

    public function __construct(private readonly EncryptionManagerInterface $encryptionManager)
    {
    }

    public function setEnabled(bool $enabled): void
    {
        $this->enabled = $enabled;
    }

    public function prePersist(EncryptionKey $encryptionKey): void
    {
        if (!$this->enabled) {
            return;
        }
        $this->masterEncryptIfNeeded($encryptionKey);
    }

    public function preUpdate(EncryptionKey $encryptionKey): void
    {
        if (!$this->enabled) {
            return;
        }
        $this->masterEncryptIfNeeded($encryptionKey);
    }

    public function postLoad(EncryptionKey $encryptionKey): void
    {
        if (!$this->enabled) {
            return;
        }
        if (!$encryptionKey->isMasterEncrypted()) {
            return;
        }
        $encryptionKey->setKey($this->encryptionManager->decryptWithMasterKey($encryptionKey->getKey()));
        $encryptionKey->setMasterEncrypted(false);
    }

    private function masterEncryptIfNeeded(EncryptionKey $encryptionKey): void
    {
        if ($encryptionKey->isMasterEncrypted()) {
            return;
        }
        $encryptionKey->setKey($this->encryptionManager->encryptWithMasterKey($encryptionKey->getKey()));
        $encryptionKey->setMasterEncrypted(true);
    }
}
