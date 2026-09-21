# MDO-CDR

**Контрольована перебудова мультимедійних файлів**

[![CI](https://github.com/WebDev-Den/phd-soft/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/WebDev-Den/phd-soft/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

MDO-CDR перевіряє зображення, аудіо та відео, перебудовує їх відповідно до обраної політики й повторно читає результат перед наданням користувачеві. Програма створює новий медіафайл лише після успішного проходження перевірок; оригінал залишається незмінним.

Доступні **вікно для Windows**, **консольна програма** та **Rust-бібліотека з C ABI**. Поточна версія — [0.1.0](https://github.com/WebDev-Den/phd-soft/blob/main/Cargo.toml).

[Швидкий старт](#швидкий-старт) · [Формати та профілі](#формати-та-профілі) · [Консольні команди](#консольні-команди) · [Для розробників](#для-розробників) · [CI та релізи](#ci-та-релізи)

## Можливості

- **Узгодження типу файла.** Аналіз байтових ознак, розширення та заявленого MIME-типу, якщо його передано.
- **Керована перебудова.** Декодування й повторне кодування медіавмісту або структурна перебудова контейнера — залежно від профілю.
- **Перевірка результату.** Повторне читання нового подання, контроль формату, сигнатур та обмежень політики.
- **Контроль надання.** Байти результату доступні лише за рішення `Clean`; за `Suspicious` або `Blocked` медіафайл не надається.
- **Звітність.** JSON із рішенням, повідомленнями, етапами оброблення, характеристиками кандидата та шляхами результатів.
- **Локальне оброблення.** Робота з файлами на комп’ютері через графічний інтерфейс, командний рядок або бібліотечний API.

## Швидкий старт

### Готовий пакет

Використовуйте пакет для своєї платформи з [Releases](https://github.com/WebDev-Den/phd-soft/releases) або розділу **Artifacts** відповідного запуску [CI](https://github.com/WebDev-Den/phd-soft/actions/workflows/ci.yml). Якщо пакет потрібної версії ще не опубліковано, [складіть програму з коду](#складання-з-коду).

| Платформа | Пакет | Спосіб запуску |
|---|---|---|
| Windows | `MDO-CDR-…-pc-windows-msvc.zip` | `Start.cmd` або `bin\mdocdr.exe` |
| Linux | `MDO-CDR-…-linux-….tar.gz` | `./bin/mdocdr` |
| macOS | `MDO-CDR-…-apple-darwin.tar.gz` | `./bin/mdocdr` |

Архітектура процесора зазначена в назві архіву. Розпакуйте його та відкрийте папку `MDO-CDR`. Готова програма не потребує Rust. Для Windows-вікна потрібні Windows PowerShell 5.1 і Windows Forms.

**На Windows:**

1. Запустіть `Start.cmd`.
2. Виберіть вхідний файл і папку результатів.
3. Залиште профіль `dissertation` та натисніть **«Обробити»**.
4. Перегляньте рішення і звіт; за успішного оброблення відкрийте створений медіафайл.

**На Linux або macOS**, із папки розпакованої програми:

```bash
./bin/mdocdr --self-test
./bin/mdocdr --input ./photo.jpg --output-dir ./results --json
```

Замініть `./photo.jpg` шляхом до свого файла. Для аудіо й відео спочатку налаштуйте FFmpeg.

### FFmpeg для аудіо та відео

Профілі `dissertation`, `strict` і `paranoid` потребують **FFmpeg та ffprobe** для оброблення аудіо й відео. У профілі `standard` FFmpeg також потрібен для остаточного декодування відеорезультату. Встановіть компоненти за інструкціями на [ffmpeg.org](https://ffmpeg.org/download.html). Для типового виходу потрібні кодери MP3 (`libmp3lame`) і H.264 (`libx264`), а для звукової доріжки відео — AAC.

Компоненти можна додати до `PATH`, передати через параметри `--ffmpeg` / `--ffprobe` або вказати змінними середовища `MDO_CDR_FFMPEG` / `MDO_CDR_FFPROBE`. Консольні параметри мають пріоритет над змінними середовища; без них програма шукає компоненти в `PATH`.

Для Windows-вікна також можна створити `runtime-paths.json` поруч зі `Start.cmd`:

```json
{
  "ffmpeg": "C:/FFmpeg/bin/ffmpeg.exe",
  "ffprobe": "C:/FFmpeg/bin/ffprobe.exe"
}
```

Вкажіть фактичні шляхи встановлення. Цей файл читає лише Windows-вікно; консольна програма використовує параметри, змінні середовища або `PATH`. FFmpeg, ffprobe та локальні налаштування не включаються до пакетів релізу.

## Формати та профілі

### Формати

| Вхідні файли | Оброблення та вихід |
|---|---|
| PNG, JPEG, статичний WebP, BMP, TIFF | Декодування пікселів і повторне кодування; типовий вихід — PNG. |
| GIF | Покадрове декодування та повторне кодування у GIF. |
| MP3, WAV, FLAC, OGG, M4A | У змістових профілях — перекодування через FFmpeg; типовий вихід — MP3. |
| MP4, WebM, Matroska | У змістових профілях — перекодування через FFmpeg у MP4 з H.264 та AAC за наявності аудіо. |
| APNG | Структурна перебудова у профілі `standard` із подальшим читанням кадрів. У змістових профілях не надається. |
| Анімований WebP, документи, архіви, виконувані файли | Не надаються поточним комплектом. |

Надання залежить від вмісту файла, доступних декодерів і обмежень профілю. Підтримка розширення не означає підтримки всіх можливих кодеків та варіантів контейнера. Перекодування може змінювати формат, метадані й характеристики медіа.

### Профілі

| Профіль | Мінімальний рівень перебудови | Максимальний вхідний файл | Призначення |
|---|---|---:|---|
| `dissertation` | Змістовий | 100 MiB | Типовий профіль CLI та Windows-вікна; у поточній версії відповідає `strict`. |
| `strict` | Змістовий | 100 MiB | Декодування й повторне кодування; обов’язкове перекодування аудіо та відео. |
| `standard` | Структурний | 200 MiB | Допускає перебудову підтримуваних контейнерів зі збереженням стисненого медіапотоку. |
| `paranoid` | Змістовий | 50 MiB | Суворіші обмеження розмірів, кількості кадрів, тривалості та бітрейту. |

**Змістова перебудова** працює з декодованими пікселями, кадрами або аудіосигналом. **Структурна перебудова** змінює контейнер, зберігаючи стиснений медіапотік. Повторне читання результату та правило надання лише за `Clean` діють в усіх профілях. Повні налаштування наведено в [`src/policy.rs`](https://github.com/WebDev-Den/phd-soft/blob/main/src/policy.rs).

## Консольні команди

Наведені нижче приклади для Windows виконуються з папки програми. На Linux/macOS використовуйте `./bin/mdocdr` і відповідні шляхи.

**Довідка та самоперевірка:**

```powershell
.\bin\mdocdr.exe --help
.\bin\mdocdr.exe --version
.\bin\mdocdr.exe --self-test
```

**Оброблення зображення:**

```powershell
.\bin\mdocdr.exe --input 'C:\Media\photo.jpg' --output-dir 'C:\Media\results' --json
```

**Оброблення відео з явними шляхами до FFmpeg:**

```powershell
.\bin\mdocdr.exe --input 'C:\Media\clip.mp4' --output-dir 'C:\Media\results' --profile dissertation --ffmpeg 'C:\FFmpeg\bin\ffmpeg.exe' --ffprobe 'C:\FFmpeg\bin\ffprobe.exe' --json
```

| Параметр | Значення |
|---|---|
| `--input FILE` | Вхідний файл; обов’язковий для оброблення. |
| `--output-dir FOLDER` | Папка результатів; створюється за потреби. |
| `--profile NAME` | `dissertation`, `standard`, `strict` або `paranoid`; типовий — `dissertation`. |
| `--mime MIME` | Необов’язковий MIME-тип, заявлений джерелом файла. |
| `--ffmpeg FILE`, `--ffprobe FILE` | Шляхи до зовнішніх компонентів. |
| `--json` | Виведення машинозчитуваного JSON у стандартний потік виведення. |
| `--self-test` | Вбудована перевірка оброблення PNG, відмови за невідповідності типу та ненадання заблокованих байтів. |
| `--help`, `--version` | Довідка або версія програми. |

Передавайте `--mime` лише тоді, коли джерело справді надало це значення. Без параметра програма аналізує байти та ім’я файла.

### Результат оброблення

За успішного оброблення папка результатів містить новий медіафайл і JSON-звіт зі спільним префіксом `ім’я.cdr-…`. За рішення про ненадання зберігається звіт без медіафайла. Наявні файли не перезаписуються.

Для автоматизації перевіряйте поле **`released`**, код завершення та `output_path`. У звіті можуть бути `candidate_sha256` і `candidate_bytes` навіть тоді, коли кандидат не дозволено надати. Повідомлення `alerts` та записи `stages` пояснюють перебіг оброблення, якщо ці дані доступні.

| Код завершення | Значення |
|---:|---|
| `0` | Результат надано; для довідки, версії та самоперевірки — успішне виконання команди. |
| `2` | Оброблення завершилося без надання медіафайла. |
| `1` | Помилка параметрів, читання, запису або невдала самоперевірка. |

Помилки до запуску оброблення, наприклад відсутній вхідний файл або перевищення розміру, можуть завершитися без файлового JSON-звіту. Параметр `--json` дає змогу отримати повідомлення про таку помилку в консолі.

## Для розробників

### Складання з коду

Потрібні Git, Rust і Cargo; для Windows — Rust MSVC та Visual Studio C++ Build Tools. CI використовує **Rust 1.98.1**. У `Cargo.toml` задекларовано мінімум 1.88, який окремо не перевіряється поточним CI. Залежності зафіксовано в `Cargo.lock`.

```bash
git clone https://github.com/WebDev-Den/phd-soft.git
cd phd-soft
```

Папка `bin/` не зберігається в Git. Після клонування спочатку складіть програму.

**Windows, PowerShell:**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Build.ps1 -Action Build
.\Start.cmd
```

Сценарій створює `bin\mdocdr.exe` та виконує самоперевірку.

**Linux або macOS:**

```bash
cargo build --release --locked --bin mdocdr
./target/release/mdocdr --self-test
./target/release/mdocdr --input ./photo.jpg --output-dir ./results --json
```

У цих командах використовується виконуваний файл із `target/release/`; готові архіви релізів містять його в `bin/`.

### Бібліотечний API

Основні типи — `FileDefender`, `DefensePolicy` і `DefenseContext`. Приклад оброблення байтів у Rust:

```rust
use mdo_cdr::{DefenseContext, FileDefender, policy::DefensePolicy};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let defender = FileDefender::new(DefensePolicy::dissertation_profile());
    let input = std::fs::read("photo.png")?;
    let result = defender.defend_bytes(
        input,
        Some("photo.png".to_owned()),
        DefenseContext::default(),
    )?;

    if result.can_release() {
        // Передавайте споживачеві лише дозволений результат.
        let output = &result.artifact.output_bytes;
        println!("Надано {} байтів", output.len());
    }
    Ok(())
}
```

Для бібліотечної інтеграції явно обирайте профіль: `DefensePolicy::default()` відповідає `standard`. Експорт C ABI та правила роботи з буферами містяться в [`src/ffi.rs`](https://github.com/WebDev-Den/phd-soft/blob/main/src/ffi.rs). Складання консольної програми разом із динамічною та статичною бібліотеками:

```bash
cargo build --release --locked --lib --bin mdocdr
```

### Локальні перевірки

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Тести охоплюють форматні обробники, узгодження типів, політики, пошкоджені файли, повторне читання, ненадання заборонених результатів, CLI та C ABI.

Окремі перевірки реального аудіо й відео потребують шляхів у змінних середовища **`MDO_TEST_FFMPEG`** і **`MDO_TEST_FFPROBE`**. Після їх налаштування запустіть:

```bash
cargo test --locked --test reconstruction_levels semantic_audio_and_video_transcode_with_external_runtime -- --ignored --exact --nocapture
cargo test --locked --test media_cli_contract cli_audio_video_roundtrip_with_external_runtime -- --ignored --exact --nocapture
```

Ці тести створюють короткі медіазразки, перевіряють перебудову та повне декодування результату. Звичайний `cargo test` пропускає їх; CI запускає їх окремо з установленим FFmpeg.

**Перевірки за дисертацією:** [матриця вимог, методика та результати](validation/README.md). Повний контрольний запуск із журналами, SHA-256, JSON і CSV:

```powershell
$env:MDO_TEST_FFMPEG = (Get-Command ffmpeg).Source
$env:MDO_TEST_FFPROBE = (Get-Command ffprobe).Source
pwsh -File ./scripts/test-dissertation.ps1
```

Перевіряються точне збереження пікселів, кадрова структура GIF, відносна зміна тривалості до 2%, двонапрямний SI-SDR аудіо від 20 дБ, SSIM відео від 0,90, ненадання, ресурсні межі та повторюваність. Звіти зберігаються у `validation/runs/`; CI додає їх як `dissertation-evidence-*` на 90 днів, зокрема в разі невдалих перевірок.

### Структура проєкту

| Шлях | Призначення |
|---|---|
| [`src/lib.rs`](https://github.com/WebDev-Den/phd-soft/blob/main/src/lib.rs) | Основний конвеєр і бібліотечний API. |
| [`src/main.rs`](https://github.com/WebDev-Den/phd-soft/blob/main/src/main.rs) | Консольна програма та JSON-звіти. |
| [`src/handlers/`](https://github.com/WebDev-Den/phd-soft/tree/main/src/handlers/) | Обробники зображень, аудіо, відео та контейнерів. |
| [`src/validation.rs`](https://github.com/WebDev-Den/phd-soft/blob/main/src/validation.rs) | Повторне читання й перевірка виходу. |
| [`src/policy.rs`](https://github.com/WebDev-Den/phd-soft/blob/main/src/policy.rs) | Профілі, обмеження та правила оброблення. |
| [`src/process.rs`](https://github.com/WebDev-Den/phd-soft/blob/main/src/process.rs) | Запуск зовнішніх компонентів із контролем часу. |
| [`src/ffi.rs`](https://github.com/WebDev-Den/phd-soft/blob/main/src/ffi.rs) | C ABI та protobuf-метадані. |
| [`crates/`](https://github.com/WebDev-Den/phd-soft/tree/main/crates/) | Допоміжні компоненти Rust workspace. |
| [`tests/`](https://github.com/WebDev-Den/phd-soft/tree/main/tests/) | Інтеграційні перевірки й тестові сценарії. |
| [`Start.ps1`](Start.ps1), [`Build.ps1`](https://github.com/WebDev-Den/phd-soft/blob/main/Build.ps1) | Windows-інтерфейс і локальне складання. |
| [`.github/workflows/`](https://github.com/WebDev-Den/phd-soft/tree/main/.github/workflows/) | CI та публікація релізів. |

## CI та релізи

[GitHub Actions](https://github.com/WebDev-Den/phd-soft/actions) автоматизує перевірки й підготовку пакетів.

| Подія | Дії |
|---|---|
| Push у будь-яку гілку або pull request | Форматування, Clippy, тести й складання на Windows, Linux та macOS; самоперевірка програми та перевірка Windows-вікна. |
| Кожен запуск CI | Окремі тести аудіо й відео з FFmpeg на Linux; формування пакетів із контрольними сумами SHA-256. |
| Ручний запуск | **Actions → CI → Run workflow**. |
| Push тега `v*` | Звірення тега з `Cargo.toml`, повний CI, перевірка контрольних сум і публікація GitHub Release. |

Підсумкова перевірка **CI passed** успішна лише після проходження всіх обов’язкових завдань. Її можна додати до правил захисту гілки на GitHub.

Пакети в **Artifacts** зберігаються **14 днів**. Кожен містить програму, бібліотеки, README, ліцензію та внутрішній `SHA256SUMS`; поруч з архівом створюється файл `.sha256`. Windows-пакет також містить `Start.cmd` і `Start.ps1`.

Для версії `0.1.0` тег релізу має бути `v0.1.0`. Теги з дефісом позначають попередній реліз. Публікація відбувається лише після успішних перевірок; push у гілку створює CI-артефакти без GitHub Release. Налаштування: [`ci.yml`](https://github.com/WebDev-Den/phd-soft/blob/main/.github/workflows/ci.yml), [`release.yml`](https://github.com/WebDev-Den/phd-soft/blob/main/.github/workflows/release.yml).

Локальне пакування після складання CLI та бібліотек потребує PowerShell 7:

```powershell
pwsh -File ./scripts/package-release.ps1
```

Архіви з’являються в `dist-packages/`, яка виключена з Git. Сценарій відмовляється перезаписувати однойменний архів.

## Межі застосування

MDO-CDR розроблено в межах дисертаційного дослідження. Профіль `dissertation` фіксує консервативну конфігурацію перебудови та надання результатів. Тести цього репозиторію перевіряють поведінку програми; вони самі по собі не відтворюють усі експерименти й кількісні результати дисертації.

Рішення `Clean` означає проходження реалізованих перевірок за обраною політикою, а не гарантію відсутності всіх загроз. Повторне читання є окремою процедурою, проте для частини форматів використовує ту саму бібліотеку декодування. Вбудовані декодери працюють у процесі програми: контроль розмірів і оброблення помилок не забезпечують повної ізоляції від вичерпання пам’яті або зависання. Для оброблення недовірених файлів у сервісах потрібні окремі обмеження ресурсів та ізоляція процесів.

## Автор і ліцензія

**Денисюк Дмитро Олександрович** · [WebDev-Den](https://github.com/WebDev-Den)

Код поширюється за [ліцензією MIT](LICENSE). Сторонні бібліотеки, FFmpeg і ffprobe мають власні ліцензійні умови.
