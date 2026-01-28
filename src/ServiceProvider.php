<?php

declare(strict_types=1);

namespace Lapix\SimpleJWTLaravel;

use Exception;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider as LaravelServiceProvider;
use Lapix\SimpleJWTLaravel\Console\Commands\CreateKeysCommand;
use Lapix\SimpleJwt\ClaimsHandler;
use Lapix\SimpleJwt\EdDSAKeys;
use Lapix\SimpleJwt\JSONWebTokenProvider;
use Lapix\SimpleJwt\OpaqueTokenFactory;
use Lapix\SimpleJwt\OpaqueTokenRepository;
use Lapix\SimpleJwt\StringGenerator;
use Lapix\SimpleJwt\SubjectRepository;
use Lapix\SimpleJwt\TokenProvider;
use Psr\EventDispatcher\EventDispatcherInterface;

class ServiceProvider extends LaravelServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(
            OpaqueTokenFactory::class,
            static fn () => new StringGenerator(),
        );

        $this->mergeConfigFrom(
            __DIR__ . '/../config/simple-jwt.php',
            'simple-jwt',
        );

        $this->app->singleton(
            EloquentOpaqueTokenRepository::class,
            static fn ($app) => new EloquentOpaqueTokenRepository(
                $app->make('db')->connection(),
                'jwt_opaque_tokens',
            ),
        );

        $this->app->when(QueueDeletionOpaqueTokenRepository::class)
            ->needs(OpaqueTokenRepository::class)
            ->give(fn () => $this->app->make(EloquentOpaqueTokenRepository::class));

        $this->app->singleton(
            OpaqueTokenRepository::class,
            fn () => $this->app->make(QueueDeletionOpaqueTokenRepository::class),
        );

        $this->app->singleton('jwt-keys', static function ($app): array {
            $config = $app->get('config');
            $privateKey = $config->get('simple-jwt.keys.0.private');
            $publicKey = $config->get('simple-jwt.keys.0.public');

            if (empty($privateKey) || empty($publicKey)) {
                throw new Exception('JWT private and public keys can\'t be empty');
            }

            return [
                new EdDSAKeys(
                    $publicKey,
                    $privateKey,
                    $config->get('simple-jwt.keys.0.id'),
                ),
            ];
        });

        $this->app->scoped(TokenProvider::class, function ($app): TokenProvider {
            $config = $app->get('config');
            $ciphers = $app->get('jwt-keys');

            $provider = new JSONWebTokenProvider(
                $ciphers,
                $app->get(OpaqueTokenFactory::class),
                $app->get(OpaqueTokenRepository::class),
                $app->get(SubjectRepository::class),
                $app->get(ClaimsHandler::class),
                $this->getPSR14Adapter(),
                $app->get('cache.store'),
            );

            return $provider->issuer($config->get('simple-jwt.issuer') ?: $config->get('app.url'))
                ->timeToLive($config->get('simple-jwt.ttl'))
                ->availableKeys($config->get('simple-jwt.use'))
                ->audience($config->get('simple-jwt.audience'))
                ->leeway($config->get('simple-jwt.leeway'))
                ->refreshTokenTimeToLive($config->get('simple-jwt.refresh_ttl'))
                ->addExpiresInClaim($config->get('simple-jwt.exi'));
        });

        $this->app->singleton(JSONWebTokenProvider::class, function (): JSONWebTokenProvider {
            return $this->app->make(TokenProvider::class);
        });

        // Add the JWT guard to the configuration.
        $config = $this->app->get('config');
        $config->set([
            'auth.guards' => array_merge($config->get('auth.guards'), [
                'jwt' => [
                    'driver' => 'jwt',
                    'provider' => $config->get('simple-jwt.guard.provider'),
                ],
            ]),
        ]);
    }

    public function boot(): void
    {
        Auth::extend('jwt', static function ($app, string $name, array $config): Guard {
            $provider = Auth::createUserProvider($config['provider']);

            if (empty($provider)) {
                throw new Exception("User provider can't be empty");
            }

            return new Guard(
                $provider,
                $app->get(ClaimsHandler::class),
                $app->get(TokenProvider::class),
                $app->get('request'),
            );
        });

        if (!$this->app->runningInConsole()) {
            return;
        }

        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        $this->publishes([
            __DIR__ . '/../config/simple-jwt.php' => config_path('simple-jwt.php'),
        ], ['simple-jwt', 'simple-jwt-config']);

        $this->publishes([
            __DIR__ . '/../stubs/ServiceProvider.stub' => app_path('Providers/SimpleJWTServiceProvider.php'),
        ], ['simple-jwt', 'simple-jwt-provider']);

        $this->commands([CreateKeysCommand::class]);
    }


    private function getPSR14Adapter(): EventDispatcherInterface
    {
        return new class ($this->app) implements EventDispatcherInterface {
            public function __construct(private Application $app)
            {
            }

            public function dispatch(object $event): object
            {
                $this->app->get('events')->dispatch($event);

                return $event;
            }
        };
    }
}
