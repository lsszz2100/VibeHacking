-- 취약한 기업 DB 초기화 스크립트
-- 교육 목적으로 의도적으로 약한 크리덴셜 사용

CREATE DATABASE IF NOT EXISTS corpdb;
USE corpdb;

-- 사용자 테이블
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role ENUM('admin', 'user', 'manager') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 민감한 데이터 테이블
CREATE TABLE IF NOT EXISTS credentials (
    id INT AUTO_INCREMENT PRIMARY KEY,
    service VARCHAR(100),
    username VARCHAR(100),
    password VARCHAR(255),
    notes TEXT
);

-- 플래그 테이블
CREATE TABLE IF NOT EXISTS flags (
    id INT AUTO_INCREMENT PRIMARY KEY,
    flag_name VARCHAR(100),
    flag_value VARCHAR(255)
);

-- 샘플 사용자 (약한 패스워드)
INSERT INTO users (username, password, email, role) VALUES
('admin',    'admin123',       'admin@corp.local',    'admin'),
('alice',    'alice123',       'alice@corp.local',    'user'),
('bob',      'password',       'bob@corp.local',      'user'),
('sysadmin', 'Sup3rS3cr3t!',   'sysadmin@corp.local', 'admin'),
('charlie',  'charlie2024',    'charlie@corp.local',  'manager');

-- 민감한 크리덴셜 (아래는 모두 CTF 실습용 가짜 데이터입니다 — 실제 유효한 자격증명이 아님)
INSERT INTO credentials (service, username, password, notes) VALUES
('AWS Production', 'iam-prod', 'FAKEKEYEXAMPLE000000', 'AWS Access Key (CTF용 가짜)'),
('GitHub',         'corp-bot', 'FAKE_CI_TOKEN_LAB_ONLY', 'CI/CD 토큰 (CTF용 가짜)'),
('Internal VPN',   'vpn-user', 'VpnP4ss!', '내부망 VPN'),
('Backup Server',  'backup',   'backup123', '야간 백업 서버'),
('LDAP',           'admin',    'admin123',  'LDAP 관리자');

-- 플래그
INSERT INTO flags (flag_name, flag_value) VALUES
('db_flag',   'FLAG{mysql_w34k_cr3d3nt14ls_pwn3d}'),
('root_flag', 'FLAG{y0u_c0mpl3t3d_full_ch41n}');

-- 추가 권한 설정 (취약: 외부 접근 허용)
-- (Docker 환경에서 MySQL 기본 설정으로 처리됨)
-- MySQL 8.0+ 방식 (IDENTIFIED BY 구문 제거, docker-compose의 환경변수로 계정 생성됨)
GRANT ALL PRIVILEGES ON corpdb.* TO 'app_user'@'%';
FLUSH PRIVILEGES;
