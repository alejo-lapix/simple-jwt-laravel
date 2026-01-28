<?php

namespace Tests\Feature;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Foundation\Auth\User;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\DatabaseTransactions;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Queue;
use Lapix\SimpleJWTLaravel\DeleteQueueToken;
use Lapix\SimpleJWTLaravel\RoutesOptions;
use Lapix\SimpleJWTLaravel\ServiceProvider;
use Lapix\SimpleJwt\JSONWebToken;
use Lapix\SimpleJwt\ClaimsHandler;
use Lapix\SimpleJwt\OpaqueTokenRepository;
use Lapix\SimpleJwt\SubjectRepository;
use Lapix\SimpleJwt\TokenProvider;
use Orchestra\Testbench\Attributes\WithMigration;
use Orchestra\Testbench\Factories\UserFactory;
use Lapix\SimpleJwt\JSONWebTokenProvider;
use Tests\TestCase;

use function Orchestra\Testbench\workbench_path;

#[WithMigration]
class JWTControllerTest extends TestCase
{
    use DatabaseMigrations;

    protected function defineEnvironment($app)
    {
        $app->get('config')->set([
            // Show the internal server errors info.
            // 'app' => ['debug' => true],
            'simple-jwt' => array_merge($app->config->get('simple-jwt'), [
                'guard' => ['name' => 'jwt'],
                'issuer' => 'https://lab.lapix.com.co',
                'keys' => [
                    [
                        'public' => 'qnfct8q2E1Pf8PU/69vL0joNLUvXyY/34hjV6OlMba0=',
                        'private' => '40nq/t9uWQlU0X+pKJKmXVDDYNyk4qv7hcfez22nMCOqd9y3yrYTU9/w9T/r28vSOg0tS9fJj/fiGNXo6UxtrQ==',
                        'id' => '101',
                    ],
                ],
            ])
        ]);
    }

    protected function setup(): void
    {
        $this->afterApplicationCreated(function () {
            $this->app->instance(SubjectRepository::class, new class () implements SubjectRepository {
                public function find(string $id): ?object
                {
                    return User::query()->findOrFail($id);
                }
            });

            $this->app->instance(ClaimsHandler::class, new class () implements ClaimsHandler {
                public function pack(object $subject): array
                {
                    return $subject->toArray();
                }

                public function unpack(JSONWebToken $jwt): object
                {
                    $properties = $jwt->getProperties();
                    $user = new \Illuminate\Foundation\Auth\User();
                    $user->id = $properties['sub'];
                    $user->name = $properties['name'];
                    $user->email = $properties['email'];
                }

                public function getSubject(object $user): string
                {
                    return (string) $user->id;
                }
            });
        });

        parent::setup();

        $this->app->get(JSONWebTokenProvider::class)
            ->setTestTimestamp(null);

        $this->app->get(\Lapix\SimpleJWTLaravel\Router::class)
            ->routes(new RoutesOptions(
                migration: [],
                management: [],
            ));
    }

    public function testFailsToCreateAToken(): void
    {
        $this->handleValidationExceptions();
        $this->post(route('token.create'), [
            'email' => 'invalid-user',
            'password' => 'password',
        ], ['accept' => 'application/json'])
            ->assertStatus(422)
            ->assertJson([
                'email' => [ 'These credentials do not match our records.' ],
            ]);
    }

    public function testCreateToken(): void
    {
        $user = UserFactory::new()->create();
        $this->handleValidationExceptions();
        $this->post(route('token.create'), [
            'email' => $user->email,
            'password' => 'password',
        ], ['accept' => 'application/json'])
            ->assertStatus(200)
            ->assertJsonStructure([
                'access_token' => [
                    'type',
                    'token',
                    'expires_in',
                ],
                'refresh_token' => [
                    'token',
                    'expires_in',
                ],
            ]);
    }

    public function testRevokeToken(): void
    {
        $user = UserFactory::new()->create();
        $set = $this->app->get(TokenProvider::class)->create($user);

        $this->post(
            route('token.revoke'),
            ['token' => $set->getRefreshToken()->getToken()],
            ['Authorization' => 'Bearer ' . $set->getJWT()->getToken()],
        )
            ->assertStatus(204);
    }

    public function testRefreshToken(): void
    {
        $user = UserFactory::new()->create();
        $set = $this->app->get(TokenProvider::class)->create($user);

        $this->post(
            route('token.refresh'),
            ['token' => $set->getRefreshToken()->getToken()],
            ['Authorization' => 'Bearer ' . $set->getJWT()->getToken()],
        )
            ->assertStatus(200)
            ->assertJsonStructure([
                'access_token' => [
                    'type',
                    'token',
                    'expires_in',
                ],
                'refresh_token' => [
                    'token',
                    'expires_in',
                ],
            ]);
    }

    public function testCreateTokenFromSession(): void
    {
        $user = UserFactory::new()->create();
        $this->actingAs($user);
        $this->post(route('token.session.create'), [], ['accept' => 'application/json'])
            ->assertStatus(200)
            ->assertJsonStructure([
                'access_token' => [
                    'type',
                    'token',
                    'expires_in',
                ],
                'refresh_token' => [
                    'token',
                    'expires_in',
                ],
            ]);
    }

    public function testRefreshTokenWithoutJWT(): void
    {
        $user = UserFactory::new()->create();
        $set = $this->app->get(TokenProvider::class)->create($user);

        $this->post(
            route('token.refresh'),
            ['token' => $set->getRefreshToken()->getToken()],
        )
            ->assertStatus(200);
    }

    /**
     * The refresh token and the JWT are not valid anymore after the
     * revoke process.
     */
    public function testInvalidateTokens(): void
    {
        $user = UserFactory::new()->create();
        $tokenProvider = $this->app->get(TokenProvider::class);
        $set = $tokenProvider->create($user);
        $tokenProvider->revoke($set->getRefreshToken()->getToken());

        $this->post(
            route('token.revoke'),
            ['token' => $set->getRefreshToken()->getToken()],
            ['Authorization' => 'Bearer ' . $set->getJWT()->getToken()],
        )
            ->assertStatus(498);
    }

    public function testWhileRevokingOnlyTheRefreshTokenIsChecked(): void
    {
        Queue::fake();

        $tokenProvider = $this->app->get(JSONWebTokenProvider::class)
            ->setTestTimestamp(1)
            ->timeToLive('31 days');
        $set = $tokenProvider->create(UserFactory::new()->create());
        // Add 32 days, now the token should be invalid.
        $tokenProvider->setTestTimestamp(60 * 60 * 24 * 32);

        $this->post(
            route('token.revoke'),
            ['token' => $set->getRefreshToken()->getToken()],
            ['Authorization' => 'Bearer ' . $set->getJWT()->getToken()],
        )
            ->assertStatus(204);

        Queue::assertPushed(DeleteQueueToken::class);
    }

    public function testInvalidRefreshTokenThrowsError(): void
    {
        $user = UserFactory::new()->create();
        $set = $this->app->get(TokenProvider::class)->create($user);

        $this->json(
            'POST',
            route('token.refresh'),
            ['token' => 'invalid-refresh-token'],
            ['Authorization' => 'Bearer ' . $set->getJWT()->getToken()],
        )
            ->assertStatus(400);
    }
}
