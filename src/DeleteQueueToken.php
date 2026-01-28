<?php

namespace Lapix\SimpleJWTLaravel;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Lapix\SimpleJwt\OpaqueToken;

class DeleteQueueToken implements ShouldQueue
{
    use Queueable, Dispatchable;

    public function __construct(
        private OpaqueToken $token,
    ) { }

    public function handle(QueueDeletionOpaqueTokenRepository $repository): void
    {
        $repository->applyDeletion($this->token);
    }
}
