<?php

namespace Gebler\EncryptedFieldsBundle\Service;

readonly class EncryptionManager
{
    public function __construct(private string $masterKey, private string $cipher = 'aes-256-gcm')
    {
        if (!\in_array($this->cipher, \openssl_get_cipher_methods())) {
            throw new \InvalidArgumentException('The cipher is not supported.');
        }
    }

    public function createEncryptionKey(): string
    {
        return \bin2hex(\random_bytes(\openssl_cipher_key_length($this->cipher)));
    }

    public function encryptWithMasterKey(string $data): string
    {
        return $this->encrypt($data, $this->masterKey);
    }

    public function decryptWithMasterKey(string $data): string
    {
        return $this->decrypt($data, $this->masterKey);
    }

    public function encrypt(string $data, string $encryptionKey): string
    {
        $encryptionKey = \hex2bin($encryptionKey);
        $keyLength = \strlen($encryptionKey);
        $cipherKeyLength = \openssl_cipher_key_length($this->cipher);
        if ($keyLength !== $cipherKeyLength) {
            throw new \InvalidArgumentException('The encryption key length is invalid.');
        }
        $ivLen = \openssl_cipher_iv_length($this->cipher);
        $iv = \random_bytes($ivLen);
        $tag = null;
        $encrypted = \openssl_encrypt(
            $data,
            $this->cipher,
            $encryptionKey,
            0,
            $iv,
            $tag,
            "",
            16
        );
        return \base64_encode($iv . $tag . $encrypted);
    }

    public function decrypt(string $data, string $encryptionKey): string
    {
        $encryptionKey = \hex2bin($encryptionKey);
        $keyLength = \strlen($encryptionKey);
        $cipherKeyLength = \openssl_cipher_key_length($this->cipher);
        if ($keyLength !== $cipherKeyLength) {
            throw new \InvalidArgumentException('The encryption key length is invalid.');
        }
        $data = \base64_decode($data);
        $ivLen = \openssl_cipher_iv_length($this->cipher);
        $iv = \substr($data, 0, $ivLen);
        $tag = \substr($data, $ivLen, 16);
        $encrypted = \substr($data, $ivLen + 16);
        return \openssl_decrypt(
            $encrypted,
            $this->cipher,
            $encryptionKey,
            0,
            $iv,
            $tag
        );
    }
}
