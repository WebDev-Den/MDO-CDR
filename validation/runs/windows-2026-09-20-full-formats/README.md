# Результати контрольної серії

Дата UTC: 2026-09-20 20:08:28Z. Успішних сценаріїв: **31/31**. Загальний результат: **True**.

Згенеровані контрольні сценарії за вимогами дисертації; це окрема серія, яка не замінює її оригінальні корпуси. Повні параметри, версії, контрольні суми та метрики — у [results.json](results.json); таблиця сценаріїв — у [cases.csv](cases.csv).

| Перевірка | Успішні тести | Невдалі | Пропущені | Код завершення | Журнал |
|---|---:|---:|---:|---:|---|
| workspace | 193 | 0 | 5 | 0 | [log](workspace.log) |
| required-reconstruction | 1 | 0 | 0 | 0 | [log](required-reconstruction.log) |
| media-cli | 1 | 0 | 0 | 0 | [log](media-cli.log) |
| audio-content | 1 | 0 | 0 | 0 | [log](audio-content.log) |
| video-content | 1 | 0 | 0 | 0 | [log](video-content.log) |

У workspace тести з FFmpeg пропущено навмисно й виконано окремими командами нижче; генератор тестових файлів не запускається. Час команд включає складання та не є оцінкою Q6. Незалежність реалізацій декодерів має статус ND.

| Сценарій | Група | Питання | Критерій виконано |
|---|---|---|---|
| Q4-png-repeat-and-fixed-point | S0 | Q4 | True |
| S0-gif-four-frames | S0 | Q1, Q4 | True |
| S0-raster-png | S0 | Q1, Q4 | True |
| S0-raster-jpg | S0 | Q1, Q4 | True |
| S0-raster-bmp | S0 | Q1, Q4 | True |
| S0-raster-tiff | S0 | Q1, Q4 | True |
| S0-raster-webp | S0 | Q1, Q4 | True |
| S1-png-text-metadata | S1 | Q1 | True |
| S2-png-truncated | S2 | Q2 | True |
| S2-png-invalid-idat | S2 | Q2 | True |
| S3-png-named-jpeg | S3 | Q2 | True |
| S3-false-declared-mime | S3 | Q2 | True |
| S3-hidden-executable-extension | S3 | Q2 | True |
| S4-png-appended-data | S4 | Q2 | True |
| S5-pixels-15-limit-16 | S5 | Q3 | True |
| S5-pixels-16-limit-16 | S5 | Q3 | True |
| S5-pixels-17-limit-16 | S5 | Q3 | True |
| S5-input-bytes-relative--1 | S5 | Q3 | True |
| S5-input-bytes-relative-0 | S5 | Q3 | True |
| S5-input-bytes-relative-1 | S5 | Q3 | True |
| S5-webp-output-expansion | S5 | Q3 | True |
| S6-plain-text | S6 | Q2 | True |
| S6-empty-zip | S6 | Q2 | True |
| S6-executable-canary | S6 | Q2 | True |
| generated_stereo_pcm16_bitrate_rejected | S5 | Q2 | True |
| generated_stereo_audio_content | S0 | Q1, Q4 | True |
| generated_mp3_audio_content | S0 | Q1, Q4 | True |
| generated_flac_audio_content | S0 | Q1, Q4 | True |
| generated_opus_audio_content | S0 | Q1, Q4 | True |
| generated_video_content | S0 | Q1, Q4 | True |
| generated_webm_video_content | S0 | Q1, Q4 | True |
