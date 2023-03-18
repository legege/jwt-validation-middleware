# JWT Validation Middleware

JWT Validation Middleware is a middleware plugin for [Traefik](https://github.com/containous/traefik) which verifies a JWT token in Auth header, Cookie or Query param, and adds the payload as injected header to the request.

## Configuration

Start with command
```yaml
command:
  - "--experimental.plugins.jwt-validation-middleware.modulename=github.com/legege/jwt-validation-middleware"
  - "--experimental.plugins.jwt-validation-middleware.version=v0.1.0"
```

Activate plugin in your config  

```yaml
http:
  middlewares:
    my-jwt-middleware:
      plugin:
        jwt-validation-middleware:
          secret: ThisIsMyVerySecret
          payloadHeader: X-Jwt-Payload
          authQueryParam: authToken
          authCookieName: authToken
```

Use as docker-compose label  
```yaml
  labels:
        - "traefik.http.routers.my-service.middlewares=my-jwt-middleware@file"
```

## Initial release

Forked from https://github.com/23deg/jwt-middleware

## Local testing

```
docker-compose -f docker-compose.test.yml up
```

```
JWT_TOKEN=...
curl -H "Host: test.host.local" "http://localhost:80/?authToken=$JWT_TOKEN" -i
curl -H "Host: test.host.local" --cookie "authToken=$JWT_TOKEN" "http://localhost:80/" -i
curl -H "Host: test.host.local" -H "Authorization: Bearer $JWT_TOKEN" "http://localhost:80/" -i
```