# gate4ai relay

Relay gate4.ai даёт устройству пользователя публичный HTTPS-адрес `https://<device-id>.<домен>`, когда до daemon `gate4ai` нельзя дойти напрямую (NAT, нет своего домена и сертификата).

**Relay необязателен.** Если у вас уже есть HTTPS до daemon (свой домен, обратный прокси, Tailscale Funnel и т. п.), relay не нужен.

Что делает:
- держит исходящий туннель устройства (WebSocket поверх TLS:443 + yamux);
- пробрасывает входящие TLS-соединения агентов по SNI **без расшифровки**: сертификат выпущен на устройство, ключ есть только у устройства;
- авторитетный DNS своей зоны: A/AAAA на себя для всех устройств, TXT `_acme-challenge.<id>` для ACME DNS-01 (устройство ставит TXT только для своего имени);
- по `--route host=addr` пробрасывает по SNI и сторонние имена (например, сайт `gate4.ai`) на локальный бэкенд — тоже без расшифровки, сертификат держит бэкенд;
- свидетель журнала: хранит подписанные чекпоинты (только хэши) и отвергает уменьшение `seq`.

Протокол — [docs/protocol.md](docs/protocol.md). Клиент устройства — в ядре: `github.com/gate4ai/gate4ai/internal/relayclient` (`gate4ai relay register`).

## Запуск

```sh
go build -o gate4ai-relay ./cmd/gate4ai-relay
gate4ai-relay --domain relay.example.org --listen :443 --dns :53 --ipv4 203.0.113.7 \
  --cert relay.crt --key relay.key --state /var/lib/gate4ai-relay/state.json
```

Сайт на том же сервере и порту 443: `--route example.org=127.0.0.1:8443` (повторяемый флаг). TLS завершает веб-сервер на `127.0.0.1:8443`; сертификат он может получать через ACME TLS-ALPN-01 — проверка проходит через relay.

Зону `relay.example.org` делегируйте (NS) на этот сервер. Для разработки — `--self-signed`, на устройстве `relay.self_signed: true` и `relay.ca_file`.

## Выкладка relay.gate4.ai

Каждый коммит в `main`, прошедший CI (тесты, сборка, e2e), выкладывается на сервер relay.gate4.ai: задача `deploy` в [ci.yml](.github/workflows/ci.yml) собирает `gate4ai-relay` под linux/amd64 (версия — `git describe`), копирует его по SSH и запускает [deploy/remote-install.sh](deploy/remote-install.sh). Скрипт заменяет только бинарник: unit systemd и `/etc/gate4ai-relay/env` (сертификат, `--route` сайта) остаются как настроены на сервере. Если после перезапуска API relay не отвечает, возвращается прежний бинарник. Перезапуск обрывает туннели устройств на пару секунд, устройства переподключаются сами.

Настройки — в окружении `production` репозитория: переменная `DEPLOY_HOST`, секреты `DEPLOY_SSH_KEY` (ключ, открытая часть которого — в `authorized_keys` root на сервере) и `DEPLOY_KNOWN_HOSTS`. Без `DEPLOY_HOST` задача пропускается. Релизы по тегу `v*` (GoReleaser) — отдельно, для self-hosted.

## Лицензия

[AGPL-3.0-only](LICENSE): изменённый relay, доступный пользователям по сети, обязан предоставлять им свой исходный код. Вклад — по CLA (подписывается в первом pull request).
