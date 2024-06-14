<?php

declare(strict_types=1);

namespace Lapix\SimpleJWTLaravel;

use Illuminate\Database\Connection;
use Lapix\SimpleJwt\OpaqueToken;
use Lapix\SimpleJwt\OpaqueTokenRepository;

use function date;
use function strtotime;

class EloquentOpaqueTokenRepository implements OpaqueTokenRepository
{
    public function __construct(
        private Connection $connection,
        private string $table,
    ) {}

    public function find(string $token): ?OpaqueToken
    {
        $row = $this->connection->table($this->table)
            ->where('token', $token)
            ->first();

        if (empty($row)) {
            return null;
        }

        return new OpaqueToken($row->token, [
            'subject' => (string) $row->owner_id,
            'expiresAt' => strtotime($row->expires_at),
        ]);
    }

    public function create(OpaqueToken $token): void
    {
        $this->connection->table($this->table)
            ->insert([
                'token' => $token->getToken(),
                'owner_id' => $token->subject,
                'expires_at' => date('Y-m-d H:i:s', $token->expiresAt),
            ]);
    }

    public function delete(OpaqueToken $token): void
    {
        $this->connection->table($this->table)
            ->where('token', $token->getToken())
            ->delete();
    }
}
