#!/bin/bash
# https://blog.naver.com/takudaddy/222220602092
# https://github.com/newbieh4cker/centos_vuln_check_script/blob/master/linux_vuln_check_script.sh

# 0. 기본 서버 설정
# 0-1. check Execute Permission
if [ "$EUID" -ne 0 ]
	then echo "root 권한으로 스크립트를 실행하여 주십시오."
	exit 1
fi

# 0-2. Locale 변경
export LANG=ko_KR.UTF-8

USERNAME="test"
PASSWD="test1234"

# 0-3. 사용자 추가 및 비밀번호 설정
useradd "${USERNAME}"
echo "${PASSWD}" | passwd --stdin "${USERNAME}"

# 0-4. 권한 추가 (/etc/sudoers)
# sed -i '/<탐색구간>/a <치환구간>' <파일경로>
sed -i "/^root\tALL/a ${USERNAME}\tALL=(ALL)\tALL" /etc/sudoers

# 0-5. Banner 설정
. ./banner_v2.0.sh

login_script

# 취얌점 진단 리스트 적용 스크립트 호출
. ./function_v2.0.sh

# ===== 취약점 진단 리스트 ===== #
# 1. 계정 관리
U01 # U-01. root 계정 원격 접속 제한
U02 # U-02. 패스워드 복잡성 설정
U03 # U-03. 계정 잠금 임계값 설정
U04 # U-04. 패스워드 최대 사용 기간 설정
U05 # U-05. 패스워드 파일 보호

# 2. 파일 및 디렉토리 관리
U06 # U-06. root 홈, 패스 디렉터리 권한 및 패스 설정
U07 # U-07. 파일 및 디렉터리 소유자 설정
U08 # U-08. /etc/passwd 파일 소유자 및 권한 설정
U09 # U-09. /etc/shadow 파일 소유자 및 권한 설정
U10 # U-10. /etc/hosts 파일 소유자 및 권한 설정
U11 # U-11. /etc/(x)inetd.conf 파일 소유자 및 권한 설정
U12 # U-12. /etc/syslog.conf 파일 소유자 및 권한 설정
U13 # U-13. /etc/services 파일 소유자 및 권한 설정
# 제외 # U-14. SUID, SGID, sticky bit 설정 파일 점검
U15 # U-15. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
# 제외 # U-16. world writable 파일 점검
# 제외 # U-17. $HOME/.rhosts, hosts.equiv 사용 금지
# 제외 # U-18. 접속 IP 및 포트 제한
U19 # U-19. cron 파일 소유자 및 권한 설정

# 3. 서비스 관리
# 제외 # U-20. Finger 서비스 비활성화
# 제외 # U-21. ANONYMOUS FTP 비활성화
# 제외 # U-22. r 계열 서비스 비활성화
# 제외 # U-23. DoS 공격에 취약한 서비스 비활성화
U24 # U-24. NFS 서비스 비활성화
# 제외 # U-25. NFS 접근통제
U26 # U-26. automountd 제거
# 제외 # U-27. RPC 서비스 확인
U28 # U-28. NIS, NIS+ 점검
# 제외 # U-29. tftp, talk 서비스 비활성화
# 제외 # U-30. Sendmail 버전 점검
# 제외 # U-31. 스팸 메일 릴레이 제한
# 제외 # U-32. 일반사용자의 Sendmail 실행 방지
# 제외 # U-33. DNS 보안 버전 패치
# 제외 # U-34. DNS ZoneTransfer 설정
