# Norder Sentry SOAR

Sentry-SIEM이 생성한 incident를 입력으로 받아 대응 Playbook을 실행하는 SOAR 파트

## 담당 범위

- `incidents.jsonl` 입력
- `recommended_playbook` 기준 대응 선택
- Sentry issue 코멘트 기록
- Slack/Discord 알림 기록
- IP 차단 후보 기록
- 코드, 시크릿, 안정성 검토 task 기록

## 실행

SIEM 결과를 입력으로 실행

```bash
python3 sentry_soar.py --incidents ../sentry-siem/incidents.jsonl --demo
```

SOAR 단독 샘플로 실행

```bash
python3 sentry_soar.py --demo
```
