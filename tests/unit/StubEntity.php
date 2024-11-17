<?php

namespace Gebler\EncryptedFieldsBundle\Tests\unit;

use Gebler\EncryptedFieldsBundle\Attribute\EncryptedField;

class StubEntity
{
    #[EncryptedField]
    private string $field;

    public function getField(): string
    {
        return $this->field;
    }

    public function setField(string $field): void
    {
        $this->field = $field;
    }
}
