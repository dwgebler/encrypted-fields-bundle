<?php

namespace Gebler\EncryptedFieldsBundle\Tests\functional\Fixtures;

use Doctrine\ORM\Mapping as ORM;
use Gebler\EncryptedFieldsBundle\Attribute\EncryptedField;

#[ORM\Entity]
#[ORM\Table(name: 'fixture_user')]
class UserEntity
{
    #[ORM\Id]
    #[ORM\Column(type: 'integer')]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private ?int $id = null;

    #[ORM\Column(type: 'string', length: 100)]
    private string $username = '';

    #[ORM\Column(type: 'text')]
    #[EncryptedField]
    private string $email = '';

    #[ORM\Column(type: 'text')]
    #[EncryptedField(useMasterKey: true)]
    private string $masterEncryptedNote = '';

    #[ORM\Column(type: 'text')]
    #[EncryptedField(key: '%gebler.encrypted_fields.test_custom_key%')]
    private string $customKeyNote = '';

    #[ORM\Column(type: 'json')]
    #[EncryptedField(elements: ['secret', 'token'])]
    private array $metadata = [];

    public function getId(): ?int { return $this->id; }

    public function getUsername(): string { return $this->username; }
    public function setUsername(string $v): void { $this->username = $v; }

    public function getEmail(): string { return $this->email; }
    public function setEmail(string $v): void { $this->email = $v; }

    public function getMasterEncryptedNote(): string { return $this->masterEncryptedNote; }
    public function setMasterEncryptedNote(string $v): void { $this->masterEncryptedNote = $v; }

    public function getCustomKeyNote(): string { return $this->customKeyNote; }
    public function setCustomKeyNote(string $v): void { $this->customKeyNote = $v; }

    public function getMetadata(): array { return $this->metadata; }
    public function setMetadata(array $v): void { $this->metadata = $v; }
}
