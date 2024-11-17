<?php

namespace Gebler\EncryptedFieldsBundle\Repository;

use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use Gebler\EncryptedFieldsBundle\Entity\EncryptionKey;

/**
 * @extends ServiceEntityRepository<EncryptionKey>
 */
class EncryptionKeyRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, EncryptionKey::class);
    }
}
