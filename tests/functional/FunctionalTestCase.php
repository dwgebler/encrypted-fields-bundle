<?php

namespace Gebler\EncryptedFieldsBundle\Tests\functional;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Logging\Middleware as LoggingMiddleware;
use Doctrine\ORM\Configuration;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Events;
use Doctrine\ORM\Mapping\Driver\AttributeDriver;
use Doctrine\ORM\Tools\SchemaTool;
use Gebler\EncryptedFieldsBundle\Doctrine\EncryptedFieldsListener;
use Gebler\EncryptedFieldsBundle\Doctrine\EncryptionKeyListener;
use Gebler\EncryptedFieldsBundle\Entity\EncryptionKey;
use Gebler\EncryptedFieldsBundle\Repository\EncryptionKeyRepository;
use Gebler\EncryptedFieldsBundle\Service\EncryptedFieldsRepository;
use Gebler\EncryptedFieldsBundle\Service\EncryptionManager;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBag;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

abstract class FunctionalTestCase extends TestCase
{
    protected EntityManagerInterface $em;
    protected EncryptionManager $encryptionManager;
    protected EncryptedFieldsRepository $fieldsRepository;
    protected EncryptedFieldsListener $listener;
    protected EncryptionKeyListener $keyListener;
    protected ParameterBagInterface $parameterBag;
    protected string $masterKey;
    /** @var list<string> */
    protected array $sqlLog = [];

    protected function setUp(): void
    {
        $this->masterKey = bin2hex(random_bytes(32));
        $customKey = bin2hex(random_bytes(32));

        $this->encryptionManager = new EncryptionManager($this->masterKey, 'aes-256-gcm');
        $this->fieldsRepository = new EncryptedFieldsRepository();
        $this->parameterBag = new ParameterBag([
            'gebler.encrypted_fields.test_custom_key' => $customKey,
        ]);

        $entityPaths = [__DIR__ . '/Fixtures'];

        $this->sqlLog = [];
        $sqlLog = &$this->sqlLog;

        $psr3Logger = new class($sqlLog) extends AbstractLogger {
            /** @param list<string> $log */
            public function __construct(private array &$log) {}

            public function log($level, string|\Stringable $message, array $context = []): void
            {
                if (isset($context['sql'])) {
                    $this->log[] = (string) $context['sql'];
                }
            }
        };

        $config = new Configuration();

        $cache = new ArrayAdapter();
        $config->setMetadataCache($cache);
        $config->setQueryCache($cache);
        $config->setResultCache($cache);

        $config->setProxyDir(sys_get_temp_dir() . '/efb-proxies-' . uniqid());
        $config->setProxyNamespace('EfbProxies');
        $config->setAutoGenerateProxyClasses(true);
        // Native lazy objects are required on PHP 8.4 because symfony/var-exporter
        // (the fallback proxy generator) requires PHP 8.4+ in the locked dep tree.
        $config->enableNativeLazyObjects(true);

        $xmlDriver = new \Doctrine\ORM\Mapping\Driver\SimplifiedXmlDriver(
            [__DIR__ . '/../../config/doctrine' => 'Gebler\\EncryptedFieldsBundle\\Entity']
        );
        $chain = new \Doctrine\Persistence\Mapping\Driver\MappingDriverChain();
        $chain->addDriver($xmlDriver, 'Gebler\\EncryptedFieldsBundle\\Entity');
        $chain->addDriver(
            new AttributeDriver($entityPaths),
            'Gebler\\EncryptedFieldsBundle\\Tests\\functional\\Fixtures'
        );
        $config->setMetadataDriverImpl($chain);

        $config->setMiddlewares([new LoggingMiddleware($psr3Logger)]);

        $connection = DriverManager::getConnection([
            'driver' => 'pdo_sqlite',
            'memory' => true,
        ], $config);

        $this->em = new EntityManager($connection, $config);

        // Patch EncryptionKey metadata: the orm.xml uses SEQUENCE generator (PostgreSQL-only).
        // Override to IDENTITY for SQLite compatibility in tests. Task 3 fixes the XML mapping.
        $keyMeta = $this->em->getClassMetadata(EncryptionKey::class);
        $keyMeta->setIdGeneratorType(\Doctrine\ORM\Mapping\ClassMetadata::GENERATOR_TYPE_IDENTITY);
        $keyMeta->setIdGenerator(new \Doctrine\ORM\Id\IdentityGenerator());
        $keyMeta->sequenceGeneratorDefinition = null;

        $schemaTool = new SchemaTool($this->em);
        $metas = $this->em->getMetadataFactory()->getAllMetadata();
        $schemaTool->createSchema($metas);

        $keyRepo = new EncryptionKeyRepository(
            new class($this->em) implements \Doctrine\Persistence\ManagerRegistry {
                public function __construct(private EntityManagerInterface $em) {}
                public function getDefaultConnectionName(): string { return 'default'; }
                public function getConnection($name = null): object { return $this->em->getConnection(); }
                public function getConnections(): array { return ['default' => $this->em->getConnection()]; }
                public function getConnectionNames(): array { return ['default' => 'default']; }
                public function getDefaultManagerName(): string { return 'default'; }
                public function getManager($name = null): \Doctrine\Persistence\ObjectManager { return $this->em; }
                public function getManagers(): array { return ['default' => $this->em]; }
                public function resetManager($name = null): \Doctrine\Persistence\ObjectManager { return $this->em; }
                public function getManagerNames(): array { return ['default' => 'default']; }
                public function getRepository($persistentObject, $persistentManagerName = null): \Doctrine\Persistence\ObjectRepository { return $this->em->getRepository($persistentObject); }
                public function getManagerForClass($class): ?\Doctrine\Persistence\ObjectManager { return $this->em; }
            }
        );

        $this->listener = new EncryptedFieldsListener(
            $this->fieldsRepository,
            $this->parameterBag,
            $this->em,
            $this->encryptionManager,
            $keyRepo,
        );
        $this->keyListener = new EncryptionKeyListener($this->encryptionManager);

        $em = $this->em->getEventManager();
        $em->addEventListener([Events::loadClassMetadata], $this->listener);
        $em->addEventListener([Events::prePersist, Events::postPersist], $this->listener);
        $em->addEventListener([Events::preUpdate, Events::postUpdate], $this->listener);
        $em->addEventListener([Events::postLoad], $this->listener);

        $keyMeta = $this->em->getClassMetadata(EncryptionKey::class);
        $keyMeta->addEntityListener('prePersist', EncryptionKeyListener::class, 'prePersist');
        $keyMeta->addEntityListener('preUpdate', EncryptionKeyListener::class, 'preUpdate');
        $keyMeta->addEntityListener('postLoad', EncryptionKeyListener::class, 'postLoad');

        $resolver = $config->getEntityListenerResolver();
        $resolver->register($this->keyListener);

        foreach ($metas as $meta) {
            $this->em->getEventManager()->dispatchEvent(
                Events::loadClassMetadata,
                new \Doctrine\ORM\Event\LoadClassMetadataEventArgs($meta, $this->em)
            );
        }
    }

    /** @return list<string> */
    protected function lastSqlMatching(string $pattern): array
    {
        return array_values(array_filter($this->sqlLog, static fn(string $sql): bool => (bool) preg_match($pattern, $sql)));
    }

    protected function clearSqlLog(): void
    {
        $this->sqlLog = [];
    }
}
