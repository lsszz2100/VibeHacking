FROM alpine:3.18
LABEL description="Internal backup tool v1.2"
LABEL maintainer="sysops@corp.local"

# 취약 패턴: 백업 크리덴셜이 이미지에 포함됨
RUN apk add --no-cache curl && \
    mkdir -p /root/.backup && \
    echo "backup_server=backup.internal.corp.local" > /root/.backup/creds.conf && \
    echo "backup_user=backupuser" >> /root/.backup/creds.conf && \
    echo "backup_password=B4ckup_P4ss!" >> /root/.backup/creds.conf && \
    echo "ssh_key_path=/root/.backup/id_rsa" >> /root/.backup/creds.conf

# 가짜 SSH 키 (교육용)
RUN echo "-----BEGIN RSA PRIVATE KEY-----" > /root/.backup/id_rsa && \
    echo "MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29SquTDrNvEhCd" >> /root/.backup/id_rsa && \
    echo "EXAMPLE_FAKE_KEY_FOR_EDUCATIONAL_PURPOSES_ONLY" >> /root/.backup/id_rsa && \
    echo "-----END RSA PRIVATE KEY-----" >> /root/.backup/id_rsa && \
    chmod 600 /root/.backup/id_rsa

CMD ["sh", "-c", "echo 'Backup Tool v1.2'; tail -f /dev/null"]
