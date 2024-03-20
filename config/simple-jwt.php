<?php

declare(strict_types=1);

return [
    'guard' => [
        'name' => env('JWT_GUARD_NAME', 'jwt'),
        'provider' => env('JWT_GUARD_PROVIDER', 'users'),
    ],

    'issuer' => env('JWT_ISSUER'),

    'model' => '\App\Modes\User',

    'ttl' => env('JWT_TTL', '+2 hours'),

    'use' => env('JWT_AVAILABLE_KEYS', 3),

    'audience' => env('JWT_AUDIENCE'),

    'leeway' => env('JWT_LEEWAY', 60),

    'refresh_ttl' => env('JWT_REFRESH_TTL', '+2 months'),

    'exi' => env('JWT_EXI', true),

    'keys' => [
        [
            'public' => env('JWT_PUBLIC_KEYS'),
            'private' => env('JWT_PRIVATE_KEYS'),
            'id' => env('JWT_IDS'),
        ],
    ],
];
