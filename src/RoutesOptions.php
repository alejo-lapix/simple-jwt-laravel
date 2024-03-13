<?php

namespace Lapix\SimpleJWTLaravel;

readonly class RoutesOptions
{
    public function __construct(
        public ?array $migration = null,
        public ?array $discovery = null,
        public ?array $authenticating = null,
        public ?array $management = null,
    ) {
    }
}
