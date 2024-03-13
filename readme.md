# Simple JWT Laravel

## Installation

You should implements the following interface and bind it.

1. First, publish the package asserts: Configuration and Service Provider.

```sh
php artisan vendor:publish --tag=simple-jwt
```

2. You should implement the following interfaces:

- `Lapix\SimpleJwt\SubjectRepository`
- `Lapix\SimpleJwt\ClaimsHandler`

3. Add the service provider to the file `/config/app.php`.

5. Generate a new key pair using the command `php artisan simple-jwt:keys` and add
the following environment variables:
- **JWT_PRIVATE_KEYS**: Private key. 
- **JWT_PUBLIC_KEYS**: Public key.
- **JWT_IDS**: An arbitrary value, it used to identify the key. 

4. Change the configuration in the file `config/simple-jwt.php` as you want.
