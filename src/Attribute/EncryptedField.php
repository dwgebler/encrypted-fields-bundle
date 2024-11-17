<?php

namespace Gebler\EncryptedFieldsBundle\Attribute;

use Attribute;

#[Attribute(Attribute::TARGET_PROPERTY)]
class EncryptedField
{
    public function __construct(
        public ?array $elements = null,
        public ?bool $useMasterKey = null,
        public ?string $key = null,
    ) {
    }
}
