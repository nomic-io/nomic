<h1 align="center">
<img src="./logo.svg" width="40%">
</h1>

Nomic Bitcoin Bridge testnet v0.4.0 (Stakenet Release Candidate)

## Stakenet

Эта тестовая сеть включает в себя все необходимое для предстоящего запуска Stakenet. (первая релизная сеть Nomic). Эта сеть не включает функциональность биткойн моста и также отключена передача токенов - только стейкинг поддерживается. Это наш последний тест, чтобы убедиться, что все в порядке для запуска.

Вы заметите много различий между Nomic и стандартыми подходами Cosmos SDK, потому что Nomic построен на полностью [кастомных решениях](https://github.com/nomic-io/orga).

## Руководство по установке валидатора

Это руководство проведет вас по шагам установки Nomic Bitcoin Bridge testnet.

Если Вам нужна какая либо помощь вы можете обратиться в  [Telegram
канал](https://t.me/nomicbtc_ru).

### Требования

- &gt;= 1GB RAM
- &gt;= 5GB of свободного мета
- Linux или macOS _(Windows пока не поддерживается)_

### 1. Сборка Nomic

Начните со сборки Nomic - в текущее время это требует Rust nightly.

```bash
# установите rustup если у вас его еще не было
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# nomic сейчас требует rust nightly
rustup default nightly

# установка необходимых зависимостей (ubuntu)
sudo apt install build-essential libssl-dev pkg-config clang

# скачивание проекта
git clone https://github.com/nomic-io/nomic.git nomic && cd nomic

# сборка и установка, добавление  `nomic` команды в путь к бинарным файлам
cargo install --path .
```

### 2. Инициализация и старнт вашей ноды

Инициализация директории с данными (`~/.nomic-stakenet-rc`) с помощью команды:

```bash
nomic init
```

Дальше, добавьте в конфиг файл seed ноды, чтобы Ваша нода могла подключиться к сети
`~/.nomic-stakenet-rc/tendermint/config/config.toml`:

```toml
# Список нод, разделенных запятотй
seeds = "dc7103629676c9bc02624887372c3e18a740c37d@167.99.228.240:26656"
```

### 3. Запустите Вашу ноду

```bash
nomic start
```

Это должно запустить Nomic state machine и Tendermint процесс.

### 4. Получание монет и стейкинг для получения права голоса

Для начала получите вад адресс `nomic balance` (ваша нода должна быть полностью синхронизированна).

Запросите монеты на Ваш адресс в телеграм канале.

После того как вы получите токены - настройте вашу ноду как валидатора и делегируйте на нее токены:

```
nomic declare \
  <validator_consensus_key> \
  <amount> \
  <commission_rate> \
  <moniker> \
  <website> \
  <identity> \
  <details>
```

- `validator_consensus_key` параметр это base64 вашего поубличного ключа `value` поле находится
под `"validator_info"` в выводе команды http://localhost:26657/status.
- `identity` поле это 64-bit hex ключ суфикс находящийся в  Keybase
  профиле, который исспользуется для получении вашей аватарки для эксплорера.

Например:
```
nomic declare \
  ohFOw5u9LGq1ZRMTYZD1Y/WrFtg7xfyBaEB4lSgfeC8= \
  10000000 \
  0.123 \
  "Foo's Validator" \
  "https://foovalidator.com" \
  37AA68F6AA20B7A8 \
  "Please delegate to me!"
```

ыСпасибо за участие в сети Nomic! Мы продолжаем улучшать сеть, так что будьте на связи  в [Telegram](https://t.me/nomicbtc_ru) для получения обновлений.
