<?php

namespace Gebler\EncryptedFieldsBundle\Tests\functional\Fixtures;

use Doctrine\ORM\Mapping as ORM;
use Gebler\EncryptedFieldsBundle\Attribute\EncryptedField;
use Symfony\Component\Uid\Uuid;

#[ORM\Entity]
#[ORM\Table(name: 'fixture_uuid')]
class UuidKeyEntity
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid')]
    private Uuid $id;

    #[ORM\Column(type: 'text')]
    #[EncryptedField]
    private string $secret = '';

    public function __construct()
    {
        $this->id = Uuid::v7();
    }

    public function getId(): Uuid { return $this->id; }
    public function getSecret(): string { return $this->secret; }
    public function setSecret(string $v): void { $this->secret = $v; }
}
