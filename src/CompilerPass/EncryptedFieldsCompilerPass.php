<?php

namespace Gebler\EncryptedFieldsBundle\CompilerPass;

use Gebler\EncryptedFieldsBundle\Attribute\EncryptedField;
use Gebler\EncryptedFieldsBundle\Service\EncryptedFieldsRepository;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Finder\Finder;

class EncryptedFieldsCompilerPass implements CompilerPassInterface
{
    private string $entityDirectory;
    private string $entityNamespace;

    public function process(ContainerBuilder $container): void
    {
        $this->entityDirectory = $container->getParameter('gebler.encrypted_fields.entities_dir');
        $this->entityNamespace = $container->getParameter('gebler.encrypted_fields.entities_namespace');
        $encryptedFieldsMap = $container->getDefinition('gebler.encrypted_fields.repository');
        $entityDirectory = $this->entityDirectory;
        $finder = new Finder();
        $finder->files()->in($entityDirectory)->name('*.php');
        foreach ($finder as $file) {
            $entityClass = rtrim($this->entityNamespace, '\\') . '\\' . $file->getBasename('.php');
            $reflectionClass = new \ReflectionClass($entityClass);
            foreach ($reflectionClass->getProperties() as $property) {
                $attribute = $property->getAttributes(EncryptedField::class);
                if (empty($attribute)) {
                    continue;
                }
                $attribute = $attribute[0]->newInstance();
                $options = [
                    'elements' => $attribute->elements,
                    'useMasterKey' => $attribute->useMasterKey,
                    'key' => $attribute->key,
                ];
                $encryptedFieldsMap->addMethodCall('addField', [$entityClass, $property->getName(), $options]);
            }
        }
    }
}
