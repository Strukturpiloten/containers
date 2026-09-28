# Compose integration for PHP-FPM images

The Nextcloud and TYPO3 images provide PHP-FPM, extensions, and utilities. They do not install either application. Install and configure the application in your own project first, including its database, web-server rules, secrets, cron or scheduler, and writable directories. This guide shows how an existing project can connect to PHP-FPM over a private Compose network; it is not a ready-to-deploy application stack.

## Nextcloud project skeleton

Put a Nextcloud installation in `./nextcloud` and an application-specific, reviewed Nginx configuration in `./nginx.conf`. That configuration must route FastCGI requests to `php:9000` and implement Nextcloud's required security and routing rules. Replace both placeholder digests with verified image digests from their publishers; check the PHP digest against this site's [image page](https://containers.strukturpiloten.de/images/nextcloud-phpfpm/) and [maintenance evidence](maintenance-evidence.md):

```yaml
services:
  php:
    image: ghcr.io/strukturpiloten/nextcloud-phpfpm:v1.0.0@sha256:REPLACE_WITH_VERIFIED_INDEX_DIGEST
    volumes:
      - ./nextcloud:/var/www/nextcloud
      - nextcloud-data:/var/www/nextcloud/data
    expose:
      - "9000"
    networks:
      - app

  web:
    image: docker.io/library/nginx@sha256:REPLACE_WITH_REVIEWED_NGINX_DIGEST
    volumes:
      - ./nextcloud:/var/www/nextcloud:ro
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    ports:
      - "127.0.0.1:8080:80"
    depends_on:
      - php
    networks:
      - app

networks:
  app:

volumes:
  nextcloud-data:
```

The web service can reach PHP-FPM as `php:9000` on the private `app` network; port 9000 is not published on the host. The web listener is bound to loopback for an integration test. Put a proper reverse proxy and HTTPS termination in front of a deployment. `depends_on` orders container startup but does not prove that PHP-FPM, the database, or Nextcloud is ready. The `nextcloud-data` volume persists user data; the project bind mount also holds application code and configuration and must be backed up. Check ownership and write permissions for the PHP worker before use. Separate writable directories or volumes may be needed for your project layout. Keep database credentials in your application's established secret/configuration mechanism; these images define no Nextcloud-specific environment-variable contract.

For an existing TYPO3 project, use `ghcr.io/strukturpiloten/typo3-phpfpm:v2.0.0@sha256:<verified-index-digest>`, mount the project at `/var/www/typo3` in both services, and use a backed-up writable volume for the project's `var/` directory (and any other project-specific persistent paths). Use TYPO3-specific Nginx/FastCGI rules, database configuration, and scheduler setup. The image version `v2.0.0` is the runtime contract version, not the TYPO3 application version.

If the stack uses notify_push, add its service on the same private network with `./nextcloud/config/config.php:/nextcloud/config/config.php:ro`. The file must be readable by UID 405. The service listens on port 7867, but real delivery also depends on Nextcloud, Redis, the database, and reverse-proxy routing; follow the [notify_push guide](../images/nextcloud/nextcloud-notifypush/README.md). Do not publish its test port or FastCGI port directly to the public network.

## Check, update, and roll back

After supplying the application installation and web-server configuration, validate the Compose file and check PHP-FPM startup:

```sh
docker compose config
docker compose up -d
docker compose exec php php -r '$s = @fsockopen("127.0.0.1", 9000, $errno, $error, 2); if (!$s) exit(1); fclose($s);'
```

These commands check wiring and PHP-FPM, not the application's installation or external services. Review web-server, database, Redis, cron/scheduler, and application logs separately. For an image maintenance update, review the new digest and evidence, back up the database and persistent data, change only the image digest in Compose, then run `docker compose pull` and `docker compose up -d`. Keep the previous digest for rollback. A container-image rollback cannot reverse an application database migration or data-format change; follow the application's own rollback guidance and restore compatible backups when needed. The [tag guide](tags-and-versions.md) explains why a readable tag plus verified digest is useful.
