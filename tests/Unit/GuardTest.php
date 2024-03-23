<?php

namespace Tests\Unit;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Lapix\SimpleJWTLaravel\Guard;
use Lapix\SimpleJwt\TokenProvider;
use Lapix\SimpleJwt\ClaimsHandler;
use Tests\TestCase;

class GuardTest extends TestCase
{
    public function testShouldIssueTheTokensAnAuthenticateTheUser(): void
    {
        $userProvider = $this->createMock(UserProvider::class);
        $claimsHandler = $this->createMock(ClaimsHandler::class);
        $tokenProvider = $this->createMock(TokenProvider::class);

        $userProvider->method('retrieveByCredentials')
            ->willReturn(new User());

        $userProvider->method('validateCredentials')
            ->willReturn(true);

        $guard = new Guard(
            $userProvider,
            $claimsHandler,
            $tokenProvider,
            new Request(),
        );

        $guard->issueTokenWithCredentialsAndAuthenticate([
            'email' => 'some-user',
            'password' => 'some-password',
        ]);

        $authenticatedUser = $guard->user();
        
        $this->assertNotEmpty($authenticatedUser);
    }
}
