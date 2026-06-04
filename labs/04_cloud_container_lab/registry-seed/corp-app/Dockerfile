FROM alpine:3.18
LABEL description="Corp production web app v2.1"
LABEL maintainer="devops@corp.local"

# 취약 패턴 1: 크리덴셜을 이미지 레이어에 하드코딩
RUN echo "DB_PASSWORD=Pr0d_DB_P4ss!" > /etc/app.conf && \
    echo "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE" >> /etc/app.conf && \
    echo "INTERNAL_API_TOKEN=secret-token-abc123xyz" >> /etc/app.conf && \
    echo "REDIS_URL=redis://:r3d1s_s3cr3t@cache.internal:6379" >> /etc/app.conf

# 취약 패턴 2: 삭제해도 이전 레이어에 크리덴셜이 남음
RUN rm /etc/app.conf

# 현재 레이어에는 버전 정보만
RUN echo "app_version=2.1.0" > /etc/version && \
    echo "build_date=2024-01-15" >> /etc/version

ENV APP_ENV=production
ENV FLAG="FLAG{r3g1stry_l4y3r_s3cr3ts_3xp0s3d}"

CMD ["sh", "-c", "echo 'Corp App v2.1 Running'; tail -f /dev/null"]
