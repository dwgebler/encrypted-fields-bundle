<?php

namespace Gebler\EncryptedFieldsBundle\Service;

use Gebler\EncryptedFieldsBundle\Exception\EncryptedFieldException;
use InvalidArgumentException;
use Random\RandomException;

readonly class EncryptionManager implements EncryptionManagerInterface
{
    public function __construct(private string $masterKey, private string $cipher = 'aes-256-gcm')
    {
        if (!\in_array($this->cipher, \openssl_get_cipher_methods())) {
            throw new InvalidArgumentException('The cipher is not supported.');
        }
    }

    /**
     * @throws RandomException
     */
    public function createEncryptionKey(): string
    {
        return \bin2hex(\random_bytes(\openssl_cipher_key_length($this->cipher)));
    }

    /**
     * @throws RandomException
     * @throws EncryptedFieldException if the data could not be encrypted
     */
    public function encryptWithMasterKey(string $data): string
    {
        return $this->encrypt($data, $this->masterKey);
    }

    /**
     * @throws EncryptedFieldException if the data could not be decrypted
     */
    public function decryptWithMasterKey(string $data): string
    {
        return $this->decrypt($data, $this->masterKey);
    }

    /**
     * @throws RandomException
     * @throws InvalidArgumentException if the encryption key length is invalid
     * @throws EncryptedFieldException if the data could not be encrypted
     */
    public function encrypt(string $data, string $encryptionKey): string
    {
        if (\strlen($data) === 0) {
            throw new InvalidArgumentException('The data is empty.');
        }
        $encryptionKey = @\hex2bin($encryptionKey);
        if ($encryptionKey === false) {
            throw new InvalidArgumentException('The encryption key is not valid.');
        }
        $keyLength = \strlen($encryptionKey);
        $cipherKeyLength = \openssl_cipher_key_length($this->cipher);
        if ($keyLength !== $cipherKeyLength) {
            throw new InvalidArgumentException('The encryption key length is invalid.');
        }
        $ivLen = \openssl_cipher_iv_length($this->cipher);
        $iv = \random_bytes($ivLen);
        $tag = null;
        $encrypted = @\openssl_encrypt(
            $data,
            $this->cipher,
            $encryptionKey,
            0,
            $iv,
            $tag,
            "",
            16
        );
        if ($encrypted === false) {
            throw new EncryptedFieldException('The data could not be encrypted: ' . \openssl_error_string());
        }
        return \base64_encode($iv . $tag . $encrypted);
    }

    /**
     * @throws EncryptedFieldException
     */
    public function decrypt(string $data, string $encryptionKey): string
    {
        if (\strlen($data) === 0) {
            throw new InvalidArgumentException('The data is empty.');
        }
        $encryptionKey = @\hex2bin($encryptionKey);
        if ($encryptionKey === false) {
            throw new InvalidArgumentException('The encryption key is not valid.');
        }
        $keyLength = \strlen($encryptionKey);
        $cipherKeyLength = \openssl_cipher_key_length($this->cipher);
        if ($keyLength !== $cipherKeyLength) {
            throw new InvalidArgumentException('The encryption key length is invalid');
        }
        $data = \base64_decode($data);
        $ivLen = \openssl_cipher_iv_length($this->cipher);
        $iv = \substr($data, 0, $ivLen);
        $tag = \substr($data, $ivLen, 16);
        $encrypted = \substr($data, $ivLen + 16);
        $decrypted = @\openssl_decrypt(
            $encrypted,
            $this->cipher,
            $encryptionKey,
            0,
            $iv,
            $tag
        );
        if ($decrypted === false) {
            throw new EncryptedFieldException('The data could not be decrypted: ' . \openssl_error_string());
        }
        return $decrypted;
    }
}
