<?php

namespace Gebler\EncryptedFieldsBundle\Tests\unit;

use Gebler\EncryptedFieldsBundle\Service\EncryptedFieldsRepository;
use PHPUnit\Framework\TestCase;

class EncryptedFieldsRepositoryTest extends TestCase
{
    private EncryptedFieldsRepository $repository;

    protected function setUp(): void
    {
        $this->repository = new EncryptedFieldsRepository();
    }

    public function testAddField(): void
    {
        $entityClass = 'TestEntity';
        $field = 'testField';
        $options = ['option1' => 'value1'];

        $this->repository->addField($entityClass, $field, $options);
        $fields = $this->repository->getFields($entityClass);

        $this->assertArrayHasKey($field, $fields);
        $this->assertEquals($options, $fields[$field]);
    }

    public function testGetFieldsReturnsEmptyArrayForUnknownEntity(): void
    {
        $fields = $this->repository->getFields('UnknownEntity');
        $this->assertEmpty($fields);
    }

    public function testGetFieldsReturnsCorrectFields(): void
    {
        $entityClass = 'TestEntity';
        $field1 = 'testField1';
        $field2 = 'testField2';
        $options1 = ['option1' => 'value1'];
        $options2 = ['option2' => 'value2'];

        $this->repository->addField($entityClass, $field1, $options1);
        $this->repository->addField($entityClass, $field2, $options2);
        $fields = $this->repository->getFields($entityClass);

        $this->assertCount(2, $fields);
        $this->assertArrayHasKey($field1, $fields);
        $this->assertArrayHasKey($field2, $fields);
        $this->assertEquals($options1, $fields[$field1]);
        $this->assertEquals($options2, $fields[$field2]);
    }
}
