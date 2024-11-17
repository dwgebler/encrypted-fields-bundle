<?php

namespace Gebler\EncryptedFieldsBundle\Service;

class EncryptedFieldsRepository
{
    public function __construct(
        private array $fields = []
    ) {
    }

    public function addField(string $entityClass, string $field, array $options): void
    {
        $this->fields[$entityClass][$field] = $options;
    }

    public function getFields(string $entityClass): array
    {
        return $this->fields[$entityClass] ?? [];
    }
}
