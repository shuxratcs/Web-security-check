# 📋 Анализ проекта SentinelAI по критериям Professionalism Report

## Структура оценки (что требуется)

Отчёт ~2000 слов по 5 секциям. Каждая секция:
1. Короткое введение
2. Аспекты, релевантные проекту + **почему** они релевантны
3. Подкреплено **ссылками** (references) на законы, стандарты, исследования

---

## 1. 📢 Social Impact (Социальное влияние)

### Что писать в отчёте:

**Положительное влияние:**
- SentinelAI **демократизирует кибербезопасность** — малые бизнесы и разработчики получают бесплатный инструмент, аналогичный коммерческим ($$$) сканерам (Burp Suite ~$449/год, Acunetix ~$4,500/год)
- **Образовательная ценность** — студенты и начинающие разработчики учатся распознавать уязвимости через визуальный интерфейс
- **Снижение киберпреступности** — по данным IBM Cost of a Data Breach Report 2024, средняя стоимость утечки данных составляет $4.88M. Раннее обнаружение экономит деньги и защищает пользователей
- Проект покрывает **OWASP Top 10** — самый авторитетный список веб-угроз

**Отрицательное влияние (dual-use):**
- Инструмент **может использоваться злоумышленниками** для поиска уязвимостей на чужих сайтах без разрешения
- **Ложное чувство безопасности** — результат "Secure" не гарантирует абсолютную безопасность
- **Цифровое неравенство** — не все организации имеют техническую грамотность для интерпретации результатов

**Как проект это решает:**
- ✅ Consent checkbox — пользователь подтверждает разрешение
- ❌ **Нужно добавить:** Disclaimer/Terms of Use на странице

### Ключевые ссылки:
- IBM (2024) *Cost of a Data Breach Report 2024*
- OWASP (2021) *OWASP Top Ten*
- NCSC (2024) *Cyber Security Breaches Survey*
- Schneier, B. (2015) *Data and Goliath: The Hidden Battles to Collect Your Data*

---

## 2. ⚖️ Ethical Issues (Этические аспекты)

### Что писать в отчёте:

**Dual-Use Dilemma:**
- Сканер безопасности — классический пример **dual-use technology** (как нож: для кухни или для преступления)
- SentinelAI отправляет **вредоносные payload'ы** (SQL injection, XSS) к целевым серверам — это **активное тестирование**, а не пассивный анализ
- Без разрешения владельца сайта это может нанести вред (нагрузка на сервер, порча данных)

**Responsible Disclosure:**
- Если сканер находит уязвимость — пользователь должен **сообщить владельцу сайта**, а не эксплуатировать
- Проект показывает remediation (исправления) — это **этичный подход**

**AI Ethics (если используется Gemini API):**
- AI может давать **неточные результаты** (hallucinations)
- Важно не полагаться слепо на AI-вердикт

**Consent и автономия:**
- Пользователь **сам решает** сканировать или нет
- Чекбокс consent — реализация принципа **informed consent**

**Как проект это решает:**
- ✅ Consent checkbox
- ✅ Remediation guidance (этичное раскрытие)
- ❌ **Нужно добавить:** Предупреждение о responsible disclosure
- ❌ **Нужно добавить:** Rate limiting (не перегружать целевой сервер)

### Ключевые ссылки:
- ACM (2018) *ACM Code of Ethics and Professional Conduct*
- BCS (2022) *BCS Code of Conduct*
- Dittrich, D. and Kenneally, E. (2012) *The Menlo Report: Ethical Principles Guiding Information and Communication Technology Research*
- NCSC (2021) *Vulnerability Disclosure Toolkit*

---

## 3. 📜 Legal Implications (Правовые аспекты)

### Что писать в отчёте:

> [!IMPORTANT]
> Это самая важная секция для проекта-сканера безопасности!

**Computer Misuse Act 1990 (UK):**
- **Section 1** — Unauthorized access to computer material (до 2 лет тюрьмы)
- **Section 3** — Unauthorized acts with intent to impair computer operation
- Сканирование сайта **без разрешения** = потенциальное нарушение CMA 1990
- SentinelAI решает это через **consent checkbox**, но юридически это не достаточная защита — нужно разрешение **владельца сайта**, а не просто нажатие чекбокса

**GDPR (General Data Protection Regulation, 2018):**
- Сканер может **собирать персональные данные** из ответов сервера (email адреса, имена в комментариях HTML)
- Module 5 (Info Disclosure) **специально ищет email** — это обработка персональных данных
- По GDPR нужно: lawful basis, data minimisation, purpose limitation
- Сканер **не хранит** данные постоянно (только в localStorage браузера) — это смягчающий фактор

**Data Protection Act 2018 (UK):**
- Имплементация GDPR в UK после Brexit
- Те же принципы применяются

**Equality Act 2010:**
- Интерфейс SentinelAI должен быть **доступен** (accessibility) — это не напрямую Equality Act, но WCAG guidelines рекомендованы
- Тёмная тема и контрастные цвета — **хорошо для accessibility**

**Copyright & Intellectual Property:**
- Использование open-source библиотек (если есть) — нужно соблюдать лицензии
- OWASP payload'ы — общедоступные, не защищены copyright

**EU Cybersecurity Act (2019) / NIS2 Directive:**
- Устанавливает стандарты кибербезопасности в ЕС
- SentinelAI помогает организациям **соответствовать требованиям** NIS2

### Ключевые ссылки:
- Computer Misuse Act 1990, c.18
- General Data Protection Regulation (EU) 2016/679
- Data Protection Act 2018, c.12
- Equality Act 2010, c.15
- ICO (2024) *Guide to the UK GDPR*
- NIS2 Directive (EU) 2022/2555

---

## 4. 🔐 Security Aspects (Аспекты безопасности)

### Что писать в отчёте:

**Безопасность самого инструмента:**
- SentinelAI работает **локально** (localhost) — не exposed to internet = меньше поверхность атаки
- Gemini API ключ хранится в `.env` — **не хардкодится** в коде (✅ хорошая практика)
- `.env` добавлен в `.gitignore` (✅ не утекает в GitHub)

**Обработка данных:**
- Результаты сканирования хранятся **только в localStorage** браузера клиента
- **Нет базы данных** на сервере — данные не persist на бэкенде
- Scan history — только локально у пользователя

**Потенциальные риски инструмента:**
- **CORS: allow_origins=["*"]** в server.py — разрешает запросы с любого домена (нужно ограничить)
- Нет **аутентификации** — любой с доступом к серверу может сканировать
- Нет **rate limiting** — можно перегрузить целевой сервер
- SSL verification отключена (`verify=False`) — необходимо для сканирования, но создаёт риск MITM

**Что проект делает хорошо:**
- ✅ Consent mechanism
- ✅ API key в .env
- ✅ Локальная работа (не cloud)
- ✅ Remediation guidance для найденных уязвимостей

**Что можно улучшить (и добавить в код!):**
- ❌ Rate limiting (макс. запросов в минуту)
- ❌ Scope control (ограничить сканирование одним доменом)
- ❌ Audit log (журнал сканирований)
- ❌ Input validation на URL

### Ключевые ссылки:
- OWASP (2023) *OWASP Testing Guide v4.2*
- NIST (2023) *Cybersecurity Framework 2.0*
- NCSC (2023) *Secure Development and Deployment Guidance*
- ISO/IEC 27001:2022 *Information Security Management*

---

## 5. 👔 Professional Practice (Профессиональная практика)

### Что писать в отчёте:

**Профессиональные организации:**
- **BCS (British Computer Society)** — Code of Conduct
  - Section 1: Public Interest — SentinelAI помогает общественной безопасности
  - Section 2: Professional Competence — использование признанных методологий (OWASP)
  - Section 3: Duty to Relevant Authority — consent mechanism
  - Section 4: Duty to the Profession — ответственное раскрытие уязвимостей

- **ACM Code of Ethics** — "avoid harm", "be honest", "respect privacy"

- **CREST (Council of Registered Ethical Security Testers)** — стандарты для pen-testers

**Рефлексия по проекту:**
- Процесс разработки (Agile/iterative)
- Принятие решений (почему выбрал Python, почему standalone)
- Личное развитие (что узнал о безопасности)

### Ключевые ссылки:
- BCS (2022) *Code of Conduct for BCS Members*
- ACM (2018) *ACM Code of Ethics*
- CREST (2023) *CREST Code of Conduct*

---

## 🛠️ Рекомендации по доработке КОДА для усиления отчёта

Эти доработки **одновременно улучшат проект И дадут материал для отчёта**:

### 1. Rate Limiting (→ Ethical + Security)
```python
# Ограничить количество запросов к целевому серверу
REQUEST_DELAY = 0.5  # секунд между запросами
```
**Для отчёта:** "Rate limiting was implemented to prevent denial-of-service on target servers, addressing ethical concerns about responsible scanning (BCS Code of Conduct, Section 1)."

### 2. Disclaimer / Terms of Use (→ Legal + Social)
Добавить текст на главную страницу:
> "This tool is for authorized security testing only. Unauthorized scanning may violate the Computer Misuse Act 1990."

### 3. Audit Log (→ Security + Professional Practice)
Логировать: кто, когда, что сканировал — для accountability.

### 4. Scope Validation (→ Legal)
Проверять, что URL не ведёт на критические системы (gov.uk, банки и т.д.)

### 5. Data Minimisation (→ GDPR/Legal)
Не показывать полные email-адреса в результатах, маскировать: `t***@example.com`

---

## 📊 Итоговая матрица: что покрыто, что нужно

| Критерий | Уже в проекте | Нужно добавить в код | Нужно для отчёта |
|----------|--------------|---------------------|-----------------|
| **Social** | Бесплатный инструмент, remediation | Disclaimer | IBM report, OWASP, NCSC refs |
| **Ethical** | Consent checkbox | Rate limiting, responsible disclosure note | ACM/BCS codes, Menlo Report |
| **Legal** | Consent, .env, .gitignore | Scope validation, data masking | CMA 1990, GDPR, DPA 2018 |
| **Security** | Local-only, env vars | Rate limiting, audit log | OWASP, NIST, ISO 27001 |
| **Professional** | OWASP methodology | — | BCS, ACM, CREST codes |

> [!TIP]
> **Стратегия на 70%+:** Для каждого критерия покажи (1) что ты ЗНАЕШЬ теорию, (2) как она ПРИМЕНЯЕТСЯ к твоему проекту, (3) что ты СДЕЛАЛ в коде в ответ на это. Три уровня = высшая оценка.
