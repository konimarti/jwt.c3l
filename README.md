## Json Web Tokens in C3

See [JWT](http://jwt.io) for more information on JSON Web Tokens (JWT).

### How to use

#### Create a token with HMAC-SHA256

```c
String payload = `{}`;
String token = jwt::encode_new(payload, "1234", JwtSigningMethod.HS256)!;
defer token.free();
```

#### Validate token and get payload

```c
String payload = jwt::decode_new(token_text, "1234", JwtSigningMethod.HS256)!;
defer payload.free();
```

### Installation

Clone the repository with
```git clone http://github.com/konimarti/jwt.c3l```
to the `./lib` folder of your C3 project and add the following to
`project.json`:

```json
{
    "dependency-search-paths": [ "lib" ],
    "dependencies": [ "jwt" ]
}
```

If you didn't clone it into the `lib` folder, adjust your
`dependency-search-paths` accordingly.

Or, as an alternative, create a git submodule: `git submodule add
github.com/konimarti/jwt.c3l lib/jwt.c3l`.
