<?php

namespace Lapix\SimpleJWTLaravel\Console\Commands;

use Illuminate\Console\Command;

class CreateKeysCommand extends Command
{
    protected $signature = 'simple-jwt:keys {--alg=}';

    protected $description = 'Prints to the STDOUT a new key pair using the given algorithm';

    public function handle(): int
    {
        $keyPair = sodium_crypto_sign_keypair();
        $privateKey = sodium_crypto_sign_secretkey($keyPair);
        $publicKey = sodium_crypto_sign_publickey($keyPair);
        $encodedPrivateKey = base64_encode($privateKey);
        $encodedPublicKey = base64_encode($publicKey);

        $this->info(sprintf('Private Key: "%s"', $encodedPrivateKey));
        $this->info(sprintf('Public Key:  "%s"', $encodedPublicKey));
 
        return self::SUCCESS;
    }
}
