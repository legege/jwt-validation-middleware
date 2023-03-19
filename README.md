# JWT Validation Middleware

JWT Validation Middleware is a middleware plugin for [Traefik](https://github.com/containous/traefik) which verifies a JWT token in Auth header, Cookie or Query param, and adds the payload as injected headers to the request.

## Configuration

Start with command
```yaml
command:
  - "--experimental.plugins.jwt-validation-middleware.modulename=github.com/legege/jwt-validation-middleware"
  - "--experimental.plugins.jwt-validation-middleware.version=v0.2.0"
```

Activate plugin in your config  

```yaml
http:
  middlewares:
    my-jwt-middleware:
      plugin:
        jwt-validation-middleware:
          secret: ThisIsMyVerySecret
          optional: true
          payloadHeaders:
            X-Custom-Header1: sub
            X-Custom-Header2: name
          authQueryParam: authToken
          authCookieName: authToken
```

Use as docker-compose label  
```yaml
  labels:
        - "traefik.http.routers.my-service.middlewares=my-jwt-middleware@file"
```

## Initial release

Inspired by code from https://github.com/23deg/jwt-middleware and https://github.com/team-carepay/traefik-jwt-plugin

## Local testing

```
docker-compose -f docker-compose.test.yml up
```

```
JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.LbfasWi8LZnBHOPAiOsroqRW7yK6mgKABkzes-iQrds"
curl -H "Host: test.host.local" "http://localhost:80/" -i
curl -H "Host: test.host.local" "http://localhost:80/?authToken=$JWT_TOKEN" -i
curl -H "Host: test.host.local" --cookie "authToken=$JWT_TOKEN" "http://localhost:80/" -i
curl -H "Host: test.host.local" -H "Authorization: Bearer $JWT_TOKEN" "http://localhost:80/" -i
```