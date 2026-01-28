<?php

namespace Lapix\SimpleJWTLaravel;

use Lapix\SimpleJwt\OpaqueToken;
use Lapix\SimpleJwt\OpaqueTokenRepository;

class QueueDeletionOpaqueTokenRepository implements OpaqueTokenRepository
{
    public function __construct(
        private OpaqueTokenRepository $decorated,
        private int $secondsLeeway = 10,
    ) {
    }

    public function find(string $token): ?OpaqueToken
    {
        return $this->decorated->find($token);
    }

    public function create(OpaqueToken $token): void
    {
        $this->decorated->create($token);
    }

    public function delete(OpaqueToken $token): void
    {
        DeleteQueueToken::dispatch($token)
            ->delay(now()->addSeconds($this->secondsLeeway));
    }

    public function applyDeletion(OpaqueToken $token): void
    {
        $this->decorated->delete($token);
    }
}
