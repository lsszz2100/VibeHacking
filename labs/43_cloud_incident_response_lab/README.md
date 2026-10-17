# Lab 43: CloudIRShield — 클라우드 사고 대응 & 침해 위협 헌팅 실습

멀티 클라우드(AWS/하이ブリッド) 환경에서의 침해사고 대응(IR) 및 위협 헌팅을 시뮬레이션하는 인터랙티브 실습 랩입니다.

## 🎯 실습 목표
1. **Stage 1 (CloudTrail Anomaly Audit)**: CloudTrail 관리 감사 로그 분석 및 비인가 외부 IP를 통한 권한 상승(`AttachUserPolicy`) 이벤트 식별
2. **Stage 2 (STS & S3 Exfiltration Forensics)**: 탈취된 임시 STS 세션 토큰(`ASIA...`)을 이용한 민감 S3 볼트(`corp-customer-pii-vault`) 대량 데이터 유출 행위 포렌식 복원
3. **Stage 3 (VPC Flow Logs Correlation)**: 프라이빗 서브넷 내부 감염 호스트(`10.0.4.15`)의 주기적 C2 비콘 통신 세션 및 포트 상관분석
4. **Stage 4 (GuardDuty Triage & Automated SOAR Containment)**: GuardDuty 심각도 8.0+ 경보 트리아지 및 자동화 SOAR(IAM 토큰 무효화, Deny 경계, 격리 보안그룹, EBS 스냅샷) 플레이북 실행

## 🚀 빠른 시작

### 로컬 실행 (Python)
```bash
cd labs/43_cloud_incident_response_lab
pip install -r requirements.txt
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8043
```

### Docker 실행
```bash
docker-compose up -d --build
```
브라우저에서 `http://127.0.0.1:8043` 접속

## 🧪 테스트 실행
```bash
pytest -v labs/43_cloud_incident_response_lab/tests/
```
