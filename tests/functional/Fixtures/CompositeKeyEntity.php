<?php

namespace Gebler\EncryptedFieldsBundle\Tests\functional\Fixtures;

use Doctrine\ORM\Mapping as ORM;
use Gebler\EncryptedFieldsBundle\Attribute\EncryptedField;

#[ORM\Entity]
#[ORM\Table(name: 'fixture_composite')]
class CompositeKeyEntity
{
    #[ORM\Id]
    #[ORM\Column(type: 'integer')]
    private int $tenantId;

    #[ORM\Id]
    #[ORM\Column(type: 'string', length: 50)]
    private string $accountCode;

    #[ORM\Column(type: 'text')]
    #[EncryptedField]
    private string $secret = '';

    public function __construct(int $tenantId, string $accountCode)
    {
        $this->tenantId = $tenantId;
        $this->accountCode = $accountCode;
    }

    public function getTenantId(): int { return $this->tenantId; }
    public function getAccountCode(): string { return $this->accountCode; }
    public function getSecret(): string { return $this->secret; }
    public function setSecret(string $v): void { $this->secret = $v; }
}
