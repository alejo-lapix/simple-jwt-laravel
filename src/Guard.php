<?php

declare(strict_types=1);

namespace Lapix\SimpleJWTLaravel;

use Exception;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard as LocalGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Lapix\SimpleJwt\ClaimsHandler;
use Lapix\SimpleJwt\ExpiredJSONWebToken;
use Lapix\SimpleJwt\TokenError;
use Lapix\SimpleJwt\TokenProvider;
use Lapix\SimpleJwt\TokenSet;
use Symfony\Component\HttpKernel\Exception\HttpException;

use function is_string;
use function strlen;

/** @property Authenticatable|null $user */
class Guard implements LocalGuard
{
    use GuardHelpers;

    // 498 Esri: Invalid token.
    private static int $refreshStatusCode = 498;

    public function __construct(
        UserProvider $provider,
        private ClaimsHandler $claimsHandler,
        private TokenProvider $tokenProvider,
        private Request $request,
        private string $header = 'Authorization',
        private string $tokenPrefix = 'Bearer',
    ) {
        $this->setProvider($provider);
    }

    public function user()
    {
        $jwt = null;
        $subject = null;

        if (! empty($this->user)) {
            return $this->user;
        }

        $token = $this->getTokenFromRequest();

        if (empty($token)) {
            return null;
        }

        try {
            $jwt = $this->tokenProvider->decode($token);
            $subject = $this->claimsHandler->unpack($jwt);
        } catch (ExpiredJSONWebToken $e) {
            throw new HttpException(self::$refreshStatusCode, $e->getMessage());
        } catch (TokenError $e) {
            // The token doesn't have a proper shape. This probably happens
            // because the users sent a 'user_token' let other guards to resolve this.
            if ($e->getMessage() === 'Wrong number of segments') {
                return null;
            }

            // If the 'kid' is not valid, maybe it's not available anymore; try
            // to generate a new jwt with the refresh token.
            if ($e->getMessage() === '"kid" invalid, unable to lookup correct key') {
                throw new HttpException(self::$refreshStatusCode, $e->getMessage());
            }

            throw new HttpException(401, $e->getMessage());
        }

        if (! $subject instanceof Authenticatable) {
            throw new Exception('Related subject is not a valid user');
        }

        $this->setUser($subject);

        return $this->user;
    }

    /** @param array{email?: string, password?: string, token?: string} $credentials */
    public function issueTokenWithCredentials(array $credentials): ?TokenSet
    {
        // TODO Emit the 'Attempt' event.
        [$valid, $user] = $this->userFromCredentialsAndValidate($credentials);

        if (! $valid || empty($user)) {
            return null;
        }

        event(new Login('jwt', $user, remember: false));

        return $this->tokenProvider->create($user);
    }

    public function issueTokenForCurrentUser(): ?TokenSet
    {
        if (empty($this->user)) {
            return null;
        }

        return $this->tokenProvider->create($this->user);
    }

    public function refreshToken(string $refreshToken): TokenSet
    {
        return $this->tokenProvider->refresh($refreshToken);
    }

    public function revokeToken(string $refreshToken): void
    {
        $this->tokenProvider->revoke($refreshToken);
    }

    /**
     * @param array{email?: string, password?: string, token?: string} $credentials
     */
    public function validate(array $credentials = [])
    {
        [$valid] = $this->userFromCredentialsAndValidate($credentials);

        return $valid;
    }

    /**
     * @param array{email?: string, password?: string, token?: string} $credentials
     *
     * @return array{0: bool, 1: Authenticatable|null}
     */
    private function userFromCredentialsAndValidate(array $credentials = []): array
    {
        $user = $this->provider->retrieveByCredentials($credentials);

        if (empty($user)) {
            return [false, null];
        }

        // TODO Emit the 'Validate' event.

        $valid = $this->provider->validateCredentials($user, $credentials);

        return [$valid, $valid ? $user : null];
    }

    private function getTokenFromRequest(): ?string
    {
        if ($this->tokenPrefix === 'Bearer') {
            return $this->request->bearerToken();
        }

        $value = $this->request->header($this->header, '');
        if (empty($value)) {
            return null;
        }

        // There are three options for the type of this variable:
        //   1) string
        //   2) null
        //   3) array
        // We discard the 2) option in the lines above and the
        // option 1) in the next line. The option 3) is available
        // but we only expect a string for this value.
        if (! is_string($value)) {
            $value = $value[0];
        }

        if (Str::startsWith($value, $this->tokenPrefix)) {
            return Str::substr($value, strlen($this->tokenPrefix . ' '));
        }

        return null;
    }
}
