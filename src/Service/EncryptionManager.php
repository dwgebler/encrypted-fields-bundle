<?php

namespace Gebler\EncryptedFieldsBundle\Service;

use Gebler\EncryptedFieldsBundle\Exception\EncryptedFieldException;
use Gebler\EncryptedFieldsBundle\Exception\InvalidEncryptedDataException;
use Gebler\EncryptedFieldsBundle\Exception\InvalidEncryptionKeyException;

class EncryptionManager implements EncryptionManagerInterface
{
    private readonly string $cipher;
    private readonly bool $authenticated;
    private readonly int $keyLengthBytes;

    public function __construct(private readonly string $masterKey, string $cipher = 'aes-256-gcm')
    {
        $normalised = strtolower($cipher);
        if (!\in_array($normalised, \openssl_get_cipher_methods(), true)) {
            throw new \InvalidArgumentException('The cipher is not supported.');
        }
        $this->cipher = $normalised;
        $this->authenticated = (bool) preg_match('/-(gcm|ccm|ocb)$/', $this->cipher);
        $this->keyLengthBytes = \openssl_cipher_key_length($this->cipher);
    }

    #[\Override]
    public function getCipher(): string
    {
        return $this->cipher;
    }

    #[\Override]
    public function getKeyLengthBytes(): int
    {
        return $this->keyLengthBytes;
    }

    #[\Override]
    public function createEncryptionKey(): string
    {
        return \bin2hex(\random_bytes($this->keyLengthBytes));
    }

    #[\Override]
    public function encryptWithMasterKey(string $data): string
    {
        return $this->encrypt($data, $this->masterKey);
    }

    #[\Override]
    public function decryptWithMasterKey(string $data): string
    {
        return $this->decrypt($data, $this->masterKey);
    }

    #[\Override]
    public function encrypt(string $data, string $encryptionKey): string
    {
        if ($data === '') {
            throw new InvalidEncryptedDataException('The data is empty.');
        }
        $rawKey = $this->decodeKey($encryptionKey);
        $ivLen = \openssl_cipher_iv_length($this->cipher);
        $iv = \random_bytes($ivLen);
        $tag = null;
        if ($this->authenticated) {
            $encrypted = @\openssl_encrypt($data, $this->cipher, $rawKey, 0, $iv, $tag, '', 16);
        } else {
            $encrypted = @\openssl_encrypt($data, $this->cipher, $rawKey, 0, $iv);
        }
        if ($encrypted === false) {
            throw new EncryptedFieldException('The data could not be encrypted: ' . \openssl_error_string());
        }
        return \base64_encode($iv . ($this->authenticated ? $tag : '') . $encrypted);
    }

    #[\Override]
    public function decrypt(string $data, string $encryptionKey): string
    {
        if ($data === '') {
            throw new InvalidEncryptedDataException('The data is empty.');
        }
        $rawKey = $this->decodeKey($encryptionKey);
        $decoded = \base64_decode($data, true);
        if ($decoded === false) {
            throw new InvalidEncryptedDataException('The data is not valid base64.');
        }
        $ivLen = \openssl_cipher_iv_length($this->cipher);
        $minLen = $ivLen + ($this->authenticated ? 16 : 0);
        if (\strlen($decoded) < $minLen) {
            throw new InvalidEncryptedDataException('The encrypted payload is shorter than the IV/tag prefix.');
        }
        $iv = \substr($decoded, 0, $ivLen);
        if ($this->authenticated) {
            $tag = \substr($decoded, $ivLen, 16);
            $ciphertext = \substr($decoded, $ivLen + 16);
            $plain = @\openssl_decrypt($ciphertext, $this->cipher, $rawKey, 0, $iv, $tag);
        } else {
            $ciphertext = \substr($decoded, $ivLen);
            $plain = @\openssl_decrypt($ciphertext, $this->cipher, $rawKey, 0, $iv);
        }
        if ($plain === false) {
            throw new EncryptedFieldException('The data could not be decrypted: ' . \openssl_error_string());
        }
        return $plain;
    }

    private function decodeKey(string $encryptionKey): string
    {
        $raw = @\hex2bin($encryptionKey);
        if ($raw === false) {
            throw new InvalidEncryptionKeyException('The encryption key is not valid hex.');
        }
        if (\strlen($raw) !== $this->keyLengthBytes) {
            throw new InvalidEncryptionKeyException(
                sprintf('Expected %d-byte key for cipher %s; got %d bytes.', $this->keyLengthBytes, $this->cipher, \strlen($raw))
            );
        }
        return $raw;
    }
}
