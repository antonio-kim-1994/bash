#!/bin/bash
. ./security_scan_v2.0.sh

if [ "$EUID" -ne 0 ]
	then echo "root 권한으로 스크립트를 실행하여 주십시오."
	exit 1
fi

Set_InitScript_Info

# ===== 취약점 진단 리스트 =====
# 1. 계정 관리
SCAN-U01 # U-01. root 계정 원격 접속 제한
SCAN-U02 # U-02. 패스워드 복잡성 설정
SCAN-U03 # U-03. 계정 잠금 임계값 설정
SCAN-U04 # U-04. 패스워드 최대 사용 기간 설정
SCAN-U05 # U-05. 패스워드 파일 보호

# 2. 파일 및 디렉토리 관리
SCAN-U06 # U-06. root 홈, 패스 디렉터리 권한 및 패스 설정
SCAN-U07 # U-07. 파일 및 디렉터리 소유자 설정
SCAN-U08 # U-08. /etc/passwd 파일 소유자 및 권한 설정
SCAN-U09 # U-09. /etc/shadow 파일 소유자 및 권한 설정
SCAN-U10 # U-10. /etc/hosts 파일 소유자 및 권한 설정
SCAN-U11 # U-11. /etc/(x)inetd.conf 파일 소유자 및 권한 설정
SCAN-U12 # U-12. /etc/syslog.conf 파일 소유자 및 권한 설정
SCAN-U13 # U-13. /etc/services 파일 소유자 및 권한 설정
SCAN-U14 # U-14. SUID, SGID, sticky bit 설정 파일 점검
SCAN-U15 # U-15. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
SCAN-U16 # U-16. world writable 파일 점검
SCAN-U17 # U-17. $HOME/.rhosts, hosts.equiv 사용 금지
# 검토 필요 # U-18. 접속 IP 및 포트 제한
SCAN-U19 # U-19. cron 파일 소유자 및 권한 설정

# 3. 서비스 관리
SCAN-U20 # U-20. Finger 서비스 비활성화
SCAN-U21 # U-21. ANONYMOUS FTP 비활성화
SCAN-U22 # U-22. r 계열 서비스 비활성화
SCAN-U23 # U-23. DoS 공격에 취약한 서비스 비활성화
SCAN-U24 # U-24. NFS 서비스 비활성화
SCAN-U25 # U-25. NFS 접근통제
SCAN-U26 # U-26. automountd 제거
SCAN-U27 # U-27. RPC 서비스 확인
SCAN-U28 # U-28. NIS, NIS+ 점검
SCAN-U29 # U-29. tftp, talk 서비스 비활성화
SCAN-U30 # U-30. Sendmail 버전 점검
SCAN-U31 # U-31. 스팸 메일 릴레이 제한
SCAN-U32 # U-32. 일반사용자의 Sendmail 실행 방지
SCAN-U33 # U-33. DNS 보안 버전 패치
SCAN-U34 # U-34. DNS ZoneTransfer 설정