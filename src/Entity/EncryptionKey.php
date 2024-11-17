<?php

namespace Gebler\EncryptedFieldsBundle\Entity;

class EncryptionKey
{
    private ?int $id = null;

    private ?string $entityClass = null;

    private ?int $entityId = null;

    private ?string $key = null;

    private bool $masterEncrypted = true;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function isMasterEncrypted(): bool
    {
        return $this->masterEncrypted;
    }

    public function setMasterEncrypted(bool $masterEncrypted): static
    {
        $this->masterEncrypted = $masterEncrypted;

        return $this;
    }

    public function getEntityClass(): ?string
    {
        return $this->entityClass;
    }

    public function setEntityClass(string $entityClass): static
    {
        $this->entityClass = $entityClass;

        return $this;
    }

    public function getEntityId(): ?int
    {
        return $this->entityId;
    }

    public function setEntityId(int $entityId): static
    {
        $this->entityId = $entityId;

        return $this;
    }

    public function getKey(): ?string
    {
        return $this->key;
    }

    public function setKey(string $key): static
    {
        $this->key = $key;

        return $this;
    }
}
