<?php

namespace Gebler\EncryptedFieldsBundle;

use Doctrine\Bundle\DoctrineBundle\DependencyInjection\Compiler\DoctrineOrmMappingsPass;
use Doctrine\Persistence\ManagerRegistry;
use Gebler\EncryptedFieldsBundle\Command\RotateEncryptionKeyCommand;
use Gebler\EncryptedFieldsBundle\Doctrine\EncryptedFieldsListener;
use Gebler\EncryptedFieldsBundle\Doctrine\EncryptionKeyListener;
use Gebler\EncryptedFieldsBundle\Entity\EncryptionKey;
use Gebler\EncryptedFieldsBundle\Repository\EncryptionKeyRepository;
use Gebler\EncryptedFieldsBundle\Service\EncryptedFieldsRepository;
use Gebler\EncryptedFieldsBundle\Service\EncryptionManager;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

class EncryptedFieldsBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->scalarNode('master_key')
                    ->isRequired()
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('cipher')
                    ->defaultValue('AES-256-GCM')
                ->end()
            ->end();
    }

    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->services()
            ->set('gebler.encrypted_fields.encryption_manager', EncryptionManager::class)
            ->args([
                '$masterKey' => $config['master_key'],
                '$cipher' => strtolower($config['cipher']),
            ])
            ->tag('container.service_arguments');
        $container->services()
            ->set('gebler.encrypted_fields.encryption_key_repository', EncryptionKeyRepository::class)
            ->args([new Reference(ManagerRegistry::class)])
            ->tag('container.service_arguments');
        $container->services()
            ->set('gebler.encrypted_fields.repository', EncryptedFieldsRepository::class)
            ->tag('container.service_arguments');
        $container->services()
            ->set('gebler.encrypted_fields.doctrine_listener', EncryptedFieldsListener::class)
            ->args([
                '$encryptionManager' => new Reference('gebler.encrypted_fields.encryption_manager'),
                '$encryptedFieldsRepository' => new Reference('gebler.encrypted_fields.repository'),
                '$parameterBag' => new Reference('parameter_bag'),
                '$em' => new Reference('doctrine.orm.default_entity_manager'),
                '$encryptionKeyRepository' => new Reference('gebler.encrypted_fields.encryption_key_repository'),
            ])
            ->tag('container.service_arguments')
            ->tag('doctrine.event_listener', ['event' => 'prePersist'])
            ->tag('doctrine.event_listener', ['event' => 'preUpdate'])
            ->tag('doctrine.event_listener', ['event' => 'postUpdate'])
            ->tag('doctrine.event_listener', ['event' => 'postLoad'])
            ->tag('doctrine.event_listener', ['event' => 'postPersist'])
            ->tag('doctrine.event_listener', ['event' => 'loadClassMetadata']);
        $container->services()
            ->set('gebler.encrypted_fields.encryption_key_entity_listener', EncryptionKeyListener::class)
            ->args([new Reference('gebler.encrypted_fields.encryption_manager')])
            ->tag('doctrine.orm.entity_listener', ['entity' => EncryptionKey::class, 'event' => 'prePersist'])
            ->tag('doctrine.orm.entity_listener', ['entity' => EncryptionKey::class, 'event' => 'preUpdate'])
            ->tag('doctrine.orm.entity_listener', ['entity' => EncryptionKey::class, 'event' => 'postLoad'])
            ->tag('container.service_arguments');
        $container->services()
            ->set('gebler.encrypted_fields.rotate_keys_command', RotateEncryptionKeyCommand::class)
            ->args([
                new Reference('gebler.encrypted_fields.encryption_manager'),
                new Reference('gebler.encrypted_fields.encryption_key_repository'),
                new Reference('gebler.encrypted_fields.repository'),
                new Reference('doctrine.orm.default_entity_manager'),
                new Reference('parameter_bag'),
            ])
            ->tag('console.command');
    }

    public function build(ContainerBuilder $container): void
    {
        $namespaces = [__DIR__.'/../config/doctrine' => 'Gebler\\EncryptedFieldsBundle\\Entity'];
        $container->addCompilerPass(
            DoctrineOrmMappingsPass::createXmlMappingDriver($namespaces)
        );
    }
}
