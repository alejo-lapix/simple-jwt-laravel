<?php

declare(strict_types=1);

namespace Lapix\SimpleJWTLaravel;

use Exception;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider as LaravelServiceProvider;
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
    public function boot(): void
    {
        Auth::extend('jwt', static function ($app, string $name, array $config): Guard {
            $provider = Auth::createUserProvider($config['provider']);

            if (empty($provider)) {
                throw new Exception('User provider can\t be empty');
            }

            return new Guard(
                $provider,
                $app->get(ClaimsHandler::class),
                $app->get(TokenProvider::class),
                $app->get('request'),
            );
        });
    }

    public function register(): void
    {
        $this->app->singleton(
            OpaqueTokenFactory::class,
            static fn () => new StringGenerator(),
        );

        $this->app->singleton(
            OpaqueTokenRepository::class,
            static fn ($app) => new EloquentOpaqueTokenRepository(
                $app->make('db')->connection(),
                'jwt_opaque_tokens',
            ),
        );

        $this->app->singleton(
            SubjectRepository::class,
            static fn ($app) => new EloquentSubjectRepository(
                $app->get('config')->get('jwt.model'),
            ),
        );

        $this->app->singleton('jwt-keys', static function ($app): array {
            $config = $app->get('config');
            $privateKey = $config->get('jwt.keys.0.private');
            $publicKey = $config->get('jwt.keys.0.public');

            if (empty($privateKey) || empty($publicKey)) {
                throw new Exception('JWT private and public keys can\'t be empty');
            }

            return [
                new EdDSAKeys(
                    $publicKey,
                    $privateKey,
                    $config->get('jwt.keys.0.id'),
                ),
            ];
        });

        $this->app->scoped(TokenProvider::class, function ($app): TokenProvider {
            $config = $app->get('config');
            $keys = $app->get('jwt-keys');

            $provider = new JSONWebTokenProvider(
                $keys,
                $app[OpaqueTokenFactory::class],
                $app[OpaqueTokenRepository::class],
                $app[SubjectRepository::class],
                $app[ClaimsHandler::class],
                $this->getPSR14Adapter(),
                $app->get('cache.store'),
            );

            return $provider->issuer($config->get('app.url'))
                ->timeToLive($config->get('jwt.ttl'))
                ->availableKeys($config->get('jwt.use'))
                ->audience($config->get('jwt.audience'))
                ->leeway($config->get('jwt.leeway'))
                ->refreshTokenTimeToLive($config->get('jwt.refresh_ttl'))
                ->addExpiresInClaim($config->get('jwt.exi'));
        });

        $this->app->singleton(JSONWebTokenProvider::class, function (): JSONWebTokenProvider {
            return $this->app->make(TokenProvider::class);
        });
    }

    private function getPSR14Adapter(): EventDispatcherInterface
    {
        return new class($this->app) implements EventDispatcherInterface {
            public function __construct(private Application $app) {}

            public function dispatch(object $event): object
            {
                $this->app->get('events')->dispatch($event);

                return $event;
            }
        };
    }
}
