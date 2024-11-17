<?php

namespace Gebler\EncryptedFieldsBundle\Doctrine;

use Gebler\EncryptedFieldsBundle\Entity\EncryptionKey;
use Gebler\EncryptedFieldsBundle\Service\EncryptionManager;

class EncryptionKeyListener
{
    public function __construct(private EncryptionManager $encryptionManager)
    {
    }

    private function preSave(EncryptionKey $encryptionKey): void
    {
        if ($encryptionKey->getKey() === null) {
            $encryptionKey->setKey($this->encryptionManager->createEncryptionKey());
        }
        $encryptionKey->setKey($this->encryptionManager->encryptWithMasterKey($encryptionKey->getKey()));
        $encryptionKey->setMasterEncrypted(true);
    }

    public function prePersist(EncryptionKey $encryptionKey): void
    {
        $this->preSave($encryptionKey);
    }

    public function preUpdate(EncryptionKey $encryptionKey): void
    {
        $this->preSave($encryptionKey);
    }

    public function postLoad(EncryptionKey $encryptionKey): void
    {
        if (!$encryptionKey->isMasterEncrypted()) {
            return;
        }
        $encryptionKey->setKey($this->encryptionManager->decryptWithMasterKey($encryptionKey->getKey()));
        $encryptionKey->setMasterEncrypted(false);
    }
}
