<?php

declare(strict_types=1);

namespace Lapix\SimpleJWTLaravel;

use Lapix\SimpleJwt\SubjectRepository;

class EloquentSubjectRepository implements SubjectRepository
{
    public function __construct(private string $className) {}

    public function find(string $id): ?object
    {
        return $this->className::query()
            ->with(['clusters' => static fn ($q) => $q->select(['id', 'name'])->limit(10)])
            ->find($id);
    }
}
