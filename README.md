# ScannerLib

Консольная утилита на C++20 для сканирования директорий на предмет вредоносных файлов по базе MD5-хешей. Рекурсивно обходит заданную директорию, вычисляет MD5 каждого файла через OpenSSL в пуле потоков и сверяет с базой. Найденные совпадения и ошибки пишутся в лог-файл, итоговая статистика — в stdout.

## Использование

```
scanner --base <csv-файл> --log <лог-файл> --path <директория> [--threads <число>]
```

- `--base` — CSV-база, формат строки: `<md5-хеш>;<вердикт>` (разделитель — точка с запятой).
- `--log` — файл лога (открывается в режиме append, родительские директории создаются автоматически).
- `--path` — корневая директория для рекурсивного сканирования.
- `--threads` — число рабочих потоков; по умолчанию `std::thread::hardware_concurrency()`.

Коды возврата: `0` — успех, `1` — фатальная ошибка, `2` — сканирование завершено, но были ошибки обработки файлов.

Пример:

```bash
./build/scanner --base hashes.csv --log scan.log --path /path/to/scan --threads 8
```

## Структура проекта

```
ScannerLib/
├── CMakeLists.txt
├── Dockerfile              # сборка под linux/amd64 (x86_64)
├── include/
│   ├── core/
│   │   ├── scanner.hpp     # оркестратор: обход директории, статистика, логирование
│   │   └── hash_base.hpp    # база хешей (CSV -> unordered_map)
│   ├── crypto/
│   │   └── md5_compute.hpp  # потоковое вычисление MD5 через OpenSSL
│   ├── threading/
│   │   ├── thread_pool.hpp  # пул потоков с ожиданием завершения задач (Wait)
│   │   └── block_queue.hpp  # блокирующая очередь на mutex + condition_variable
│   └── utils/
│       ├── logger.hpp      # потокобезопасный синглтон-логгер (файл + консоль)
│       └── validate_path.hpp# валидация путей (база, лог, директория)
└── src/                    # реализация, зеркалит include/
    ├── core/
    ├── crypto/
    ├── utils/
    └── main.cpp            # CLI: разбор аргументов через getopt_long
```

## Требования

- Компилятор с поддержкой C++20 (GCC 11+, Clang 13+, MSVC 2022+)
- CMake ≥ 3.20
- OpenSSL (libcrypto)
- pthreads
- Либо Docker (для сборки без установки тулчейна)

## Сборка

Нативно:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

На macOS OpenSSL берётся из Homebrew автоматически (пути `/opt/homebrew/opt/openssl` и `/usr/local/opt/openssl` добавлены в `CMAKE_PREFIX_PATH`). При другой установке OpenSSL укажите `CMAKE_PREFIX_PATH` вручную.

OpenSSL ≥ 3.0 помечает `MD5_Init/Update/Final` как deprecated — предупреждения компилятора ожидаемы, это не ошибка.

## Сборка в Docker (x86_64)

Multi-stage Dockerfile собирает бинарь под `linux/amd64` независимо от архитектуры хоста (в том числе на Apple Silicon, через эмуляцию):

```bash
docker build --platform=linux/amd64 -t scannerlib .
```

Запуск с монтированием каталога данных:

```bash
docker run --rm --platform=linux/amd64 \
    -v "$PWD/data:/data" \
    scannerlib --base /data/hashes.csv --log /data/scan.log --path /data/scan
```

## Тестирование

Тесты на GoogleTest (без моков, реальная файловая система): unit-тесты для `HashBase`, `MD5Compute`, `BlockQueue`, `ThreadPool`, `PathChecker` и интеграционные тесты `Scanner` (сквозное сканирование временной директории).

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release   # тесты включены по умолчанию (-DSCANNER_BUILD_TESTS=ON)
cmake --build build -j
cd build && ctest --output-on-failure
```

На macOS GTest берётся из Homebrew (`brew install googletest`, пути уже добавлены в `CMAKE_PREFIX_PATH`). Для сборки без тестов: `-DSCANNER_BUILD_TESTS=OFF`.

## Примечания

- MD5 криптографически устарел — здесь он используется только как формат сигнатурной базы.
- Утилита читает произвольные файлы по указанному пути; не запускайте с повышенными привилегиями без необходимости. Лог-файл может содержать чувствительные пути файловой системы.
