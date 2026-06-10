# Norder Sentry SIEM

Sentry 이벤트를 보안 운영 데이터로 재분류하는 SIEM 파트입니다.

## 담당 범위

- Sentry 이벤트 입력
- 보안 탐지 시나리오 적용
- 여러 Sentry 이벤트를 security incident로 묶기
- triage 로직으로 위험도와 공격 가능성 판단
- SOAR가 읽을 `incidents.jsonl` 생성

## 실행

```bash
python3 sentry_siem.py --demo
```

결과:

```text
incidents.jsonl
```

이 파일을 `sentry-soar` 폴더에서 입력으로 사용합니다.
