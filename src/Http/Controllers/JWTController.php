<?php

declare(strict_types=1);

namespace Lapix\SimpleJWTLaravel\Http\Controllers;

use Exception;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Cache;
use Lapix\SimpleJWTLaravel\Guard;
use Lapix\SimpleJwt\AsymetricCipher;
use Lapix\SimpleJwt\EllipticCurveAware;
use Lapix\SimpleJwt\ExpiredRefreshToken;
use Lapix\SimpleJwt\TokenError;
use Lapix\SimpleJwt\TokenSet;

use function array_map;
use function config;
use function time;

class JWTController
{
    private array $updateCreateRules = [];

    public function __construct(private Application $app) {}

    /**
     * Add a new callback to update the validation rules before
     * checking it against the incoming request.
     */
    public function addCreateRules(\Closure $cb): void
    {
        $this->updateCreateRules[] = $cb;
    }

    /**
     * Creates a new JSON Web Token with the given credentials.
     */
    public function create(Request $request): JsonResponse
    {
        $rules = [
            'email' => 'required|string',
            'password' => 'required|string',
        ];

        foreach ($this->updateCreateRules as $update) {
            $rules = $update($rules);
        }

        $request->validate($rules);

        $guard = $this->getGuard();
        $tokenSet = $guard->issueTokenWithCredentials($request->only('email', 'password'));

        if (empty($tokenSet)) {
            return $this->response()->json([
                'email' => [
                    $this->app->get('translator')->get('auth.failed'),
                ],
            ], 422);
        }

        return $this->presentTokenSet($tokenSet);
    }

    /**
     * This method is useful for the migration process to the JWT
     * usage, we'll create the token if the user is authenticated
     * with any other token guard.
     */
    public function createTokenFromSession(Request $request): JsonResponse
    {
        $user = $request->user();

        if (empty($user)) {
            throw new Exception('User is not authenticated');
        }

        $tokenSet = $this->getGuard()
            ->setUser($user)
            ->issueTokenForCurrentUser();

        if (empty($tokenSet)) {
            throw new Exception('Can\'t create the token set');
        }

        return $this->presentTokenSet($tokenSet);
    }

    /**
     * Revoke refresh tokens, user need to authenticate again.
     */
    public function revoke(Request $request): JsonResponse|Response
    {
        $guard = $this->getGuard();

        try {
            $guard->revokeToken($request->input('token'));
        } catch (TokenError $e) {
            return $this->response()->json([
                'error' => $e->getMessage(),
            ], 498);
        }

        return $this->response()->noContent();
    }

    /**
     * Created a new token set, user should provide a valid refresh token.
     */
    public function refresh(Request $request): JsonResponse
    {
        $tokenSet = null;

        try {
            // First, lock the current 
            $tokenSet = $this->atomicRefresh($request->token);

        } catch (ExpiredRefreshToken $e) {
            // 440 IIS: Login time-out.
            return $this->response()->json([
                'message' => $e->getMessage(),
            ], 440);
        } catch (TokenError $e) {
            return $this->response()->json([
                'message' => $e->getMessage(),
            ], 400);
        }

        return $this->presentTokenSet($tokenSet);
    }

    /**
     * Show the tokens used to sign the JWT.
     */
    public function keys(): JsonResponse
    {
        $keys = array_map(
            static function (AsymetricCipher $cipher): array {
                $key = [
                    'kty' => $cipher->getType(),
                    'alg' => $cipher->getName(),
                    'x' => $cipher->getPublicKey(),
                    'kid' => $cipher->getID(),
                ];

                if ($cipher instanceof EllipticCurveAware) {
                    $key['crv'] = $cipher->getEllipticCurveName();
                }

                return $key;
            },
            $this->app->get('jwt-keys'),
        );

        return $this->response()
            ->json(['keys' => $keys]);
    }

    private function presentTokenSet(TokenSet $tokenSet): JsonResponse
    {
        return $this->response()->json([
            'access_token' => [
                'type' => 'Bearer',
                'token' => $tokenSet->getJWT()->getToken(),
                'expires_in' => $tokenSet->getJWT()->exi,
            ],
            'refresh_token' => [
                'token' => $tokenSet->getRefreshToken()->getToken(),
                'expires_in' => $tokenSet->getRefreshToken()->expiresAt - time(),
            ],
        ]);
    }

    private function getGuard(): Guard
    {
        $guard = $this->app->get('auth')->guard(
            $this->app->get('config')->get('simple-jwt.guard.name'),
        );

        if (! $guard instanceof Guard) {
            throw new Exception(
                sprintf('Expected a JWT Guard but got: "%s"', $guard::class),
            );
        }

        return $guard;
    }

    private function response(): ResponseFactory
    {
        return $this->app->get(ResponseFactory::class);
    }

    private function atomicRefresh(string $token): TokenSet
    {
        $tokenSet = null;
        $guard = $this->getGuard();

        $lockKey = 'lock_jwt_refresh:' . $token;
        $cacheKey = 'cache_jwt_refresh:' . $token;

        $lock = Cache::lock($lockKey, seconds: 10);

        try {
            if ($lock->get()) {
                $tokenSet = $guard->refreshToken($token);
                Cache::put($cacheKey, $tokenSet, ttl: 10);

                return $tokenSet;
            }

            // Wait for one second to get the token set.
            for ($i = 0; $i < 10; $i++) {
                usleep(1000 * 100);

                $tokenSet = Cache::get($cacheKey);
                if (! empty($tokenSet)) {
                    return $tokenSet;
                }

                if ($lock->get()) {
                    $tokenSet = $guard->refreshToken($token);
                    Cache::put($cacheKey, $tokenSet, ttl: 10);
                    return $tokenSet;
                }
            }

            // The server is having troubles, just failed to create or retrieve the JWT.
            throw new \Exception('Timeout waiting to the the refresh token');

        } finally {
            $lock->release();
        }
    }
}
