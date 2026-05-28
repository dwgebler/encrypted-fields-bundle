<?php

namespace Gebler\EncryptedFieldsBundle\Service;

use Gebler\EncryptedFieldsBundle\Exception\EncryptedFieldException;

interface EncryptionManagerInterface
{
    public function createEncryptionKey(): string;

    /** @throws EncryptedFieldException */
    public function encryptWithMasterKey(string $data): string;

    /** @throws EncryptedFieldException */
    public function decryptWithMasterKey(string $data): string;

    /** @throws EncryptedFieldException */
    public function encrypt(string $data, string $encryptionKey): string;

    /** @throws EncryptedFieldException */
    public function decrypt(string $data, string $encryptionKey): string;

    public function getCipher(): string;

    public function getKeyLengthBytes(): int;
}
