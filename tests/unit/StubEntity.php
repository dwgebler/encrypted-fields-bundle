<?php

namespace Gebler\EncryptedFieldsBundle\Tests\unit;

use Doctrine\ORM\Mapping as ORM;
use Gebler\EncryptedFieldsBundle\Attribute\EncryptedField;

#[ORM\Entity]
class StubEntity
{
    #[ORM\Id]
    #[ORM\Column(type: 'integer')]
    #[ORM\GeneratedValue(strategy: 'AUTO')]
    private ?int $id = null;

    #[EncryptedField]
    private string $field;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function setId(int $id): void
    {
        $this->id = $id;
    }

    public function getField(): string
    {
        return $this->field;
    }

    public function setField(string $field): void
    {
        $this->field = $field;
    }
}
