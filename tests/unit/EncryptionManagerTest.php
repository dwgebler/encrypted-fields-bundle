<?php

namespace Gebler\EncryptedFieldsBundle\Tests\unit;

use Gebler\EncryptedFieldsBundle\Exception\EncryptedFieldException;
use Gebler\EncryptedFieldsBundle\Exception\InvalidEncryptedDataException;
use Gebler\EncryptedFieldsBundle\Exception\InvalidEncryptionKeyException;
use Gebler\EncryptedFieldsBundle\Service\EncryptionManager;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Random\RandomException;

class EncryptionManagerTest extends TestCase
{
    private EncryptionManager $encryptionManager;
    private string $masterKey;

    protected function setUp(): void
    {
        $this->masterKey = bin2hex(random_bytes(32)); // 256-bit key for AES-256-GCM
        $this->encryptionManager = new EncryptionManager($this->masterKey);
    }

    public function testCreateEncryptionKey(): void
    {
        $key = $this->encryptionManager->createEncryptionKey();
        $this->assertEquals(64, strlen($key)); // 32 bytes in hex is 64 characters
    }

    public function testEncryptDecryptWithAesCbc(): void
    {
        $data = 'test data';
        $encryptionManager = new EncryptionManager($this->masterKey, 'aes-256-cbc');
        $encrypted = $encryptionManager->encrypt($data, $this->masterKey);
        $decrypted = $encryptionManager->decrypt($encrypted, $this->masterKey);
        $this->assertEquals($data, $decrypted);
    }

    public function testEncryptWithMasterKey(): void
    {
        $data = 'test data';
        $encrypted = $this->encryptionManager->encryptWithMasterKey($data);
        $this->assertNotEquals($data, $encrypted);
    }

    public function testDecryptWithMasterKey(): void
    {
        $data = 'test data';
        $encrypted = $this->encryptionManager->encryptWithMasterKey($data);
        $decrypted = $this->encryptionManager->decryptWithMasterKey($encrypted);
        $this->assertEquals($data, $decrypted);
    }

    public function testEncryptWithInvalidKeyLength(): void
    {
        $this->expectException(InvalidEncryptionKeyException::class);
        $this->encryptionManager->encrypt('test data', 'shortkey');
    }

    public function testDecryptWithInvalidKeyLength(): void
    {
        $this->expectException(InvalidEncryptionKeyException::class);
        $this->encryptionManager->decrypt('test data', 'shortkey');
    }

    public function testEncryptAndDecrypt(): void
    {
        $data = 'test data';
        $encryptionKey = $this->encryptionManager->createEncryptionKey();
        $encrypted = $this->encryptionManager->encrypt($data, $encryptionKey);
        $decrypted = $this->encryptionManager->decrypt($encrypted, $encryptionKey);
        $this->assertEquals($data, $decrypted);
    }

    public function testEncryptWithInvalidCipher(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The cipher is not supported.');
        new EncryptionManager($this->masterKey, 'invalid-cipher');
    }

    public function testEncryptThrowsExceptionOnEmptyData(): void
    {
        $this->expectException(InvalidEncryptedDataException::class);
        $this->expectExceptionMessage('The data is empty.');
        $this->encryptionManager->encrypt('', $this->masterKey);
    }

    public function testDecryptThrowsExceptionOnEmptyData(): void
    {
        $this->expectException(InvalidEncryptedDataException::class);
        $this->expectExceptionMessage('The data is empty.');
        $this->encryptionManager->decrypt('', $this->masterKey);
    }

    public function testDecryptThrowsExceptionOnInvalidData(): void
    {
        $this->expectException(EncryptedFieldException::class);
        $this->encryptionManager->decrypt('invalid data', $this->masterKey);
    }

    public function testGetCipherReturnsNormalisedLowercase(): void
    {
        $manager = new EncryptionManager($this->masterKey, 'AES-256-GCM');
        $this->assertSame('aes-256-gcm', $manager->getCipher());
    }

    public function testGetKeyLengthBytesMatchesOpenSsl(): void
    {
        $this->assertSame(32, $this->encryptionManager->getKeyLengthBytes());
    }

    public function testDecryptThrowsInvalidEncryptedDataExceptionOnEmpty(): void
    {
        $this->expectException(InvalidEncryptedDataException::class);
        $this->encryptionManager->decrypt('', $this->masterKey);
    }

    public function testDecryptThrowsInvalidEncryptionKeyExceptionOnBadKey(): void
    {
        $this->expectException(InvalidEncryptionKeyException::class);
        $this->encryptionManager->decrypt('somedata', 'not-hex');
    }
}
