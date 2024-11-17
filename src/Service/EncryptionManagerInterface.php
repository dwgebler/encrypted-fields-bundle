<?php

namespace Gebler\EncryptedFieldsBundle\Service;

interface EncryptionManagerInterface
{
    public function createEncryptionKey(): string;
    public function encryptWithMasterKey(string $data): string;
    public function decryptWithMasterKey(string $data): string;
    public function encrypt(string $data, string $encryptionKey): string;
    public function decrypt(string $data, string $encryptionKey): string;
}
