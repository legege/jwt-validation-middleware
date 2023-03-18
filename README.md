# JWT Validation Middleware

JWT Validation Middleware is a middleware plugin for [Traefik](https://github.com/containous/traefik) which verifies a JWT token in Auth header, Cookie or Query param, and adds the payload as injected header to the request.

## Configuration

Start with command
```yaml
command:
  - "--experimental.plugins.jwt-middleware.modulename=github.com/legege/jwt-middleware"
  - "--experimental.plugins.jwt-middleware.version=v0.1.0"
```

Activate plugin in your config  

```yaml
http:
  middlewares:
    my-jwt-middleware:
      plugin:
        jwt-middleware:
          secret: SECRET
          payloadHeader: X-Jwt-Payload
          authQueryParam: authToken
          authCookieName: authToken
```

Use as docker-compose label  
```yaml
  labels:
        - "traefik.http.routers.my-service.middlewares=my-jwt-middleware@file"
```

Forked from https://github.com/23deg/jwt-middleware