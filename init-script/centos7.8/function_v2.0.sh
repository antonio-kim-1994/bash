#!/bin/bash

# 1. 진단 스크립트
# 1-1. 시스템 정보
RESULT=/root/$(hostname)"_scan_result_"$(date +%F).txt

# ANSI 색상 코드
GREEN='\033[32m'
RED='\033[31m'
SKY='\033[36m'
RESET='\033[0m'

SPACE(){
echo -e "" >> "$RESULT"
}

OK() {
  echo -e "${GREEN}[ 양호 ] : $*${RESET}" >> "$RESULT"
}

# WARN 메시지 출력
WARN() {
  echo -e "${RED}[ 취약 ] : $*${RESET}" >> "$RESULT"
}

BAR() {
echo "========================================================================"  >> "$RESULT"
}

CODE(){
echo -e "${SKY}$*${RESET}" >> "$RESULT"
}

Set_InitScript_Info() {
{
  echo "
  **********************************************************************
  *                           리눅스 스크립트                          *
  **********************************************************************
    항목에 따라 시간이 다른 항목에 비하여 다소 오래 걸릴수 있습니다.
    스캔 보고서는 hostname_scan_result_시간.txt 파일로 /root에 저장 됩니다.
    기준은 [CSAP 클라우드 취약점 점검 가이드] 문서입니다.
  **********************************************************************

  ############################# 시작 시간 ##############################
  $(date)

  ============================  시스템  정보 ===========================
  1. 시스템 기본 정보
     운영체제: $(head -n 1 /etc/centos-release)
     호스트 이름: $(uname -n)
     커널 버전: $(uname -r)

  2. 네트워크 정보
  $(ifconfig -a)

  ************************** 취약점 체크 시작 **************************
  "
} >> "$RESULT"
}

# 1. 계정 관리
# U-01. root 계정 원격 접속 제한
# 양호 : 원격 터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우
# 취약 : 원격 터미널 서비스 사용 시 root 직접 접속을 허용한 경우
U01(){
  SECURETTY_Path=/etc/securetty
  SSHD_Path=/etc/ssh/sshd_config
  if grep -q '^pts' "${SECURETTY_Path}"; then
    sed -i "s/^pts/#pts/g" "${SECURETTY_Path}"
  fi

  if [ "$(grep 'PermitRootLogin' "${SSHD_Path}")" != "PermitRootLogin no" ]; then
    sed -i -r "/^(#?PermitRootLogin)/ c\\PermitRootLogin no" "${SSHD_Path}"
  fi
}

# U-02. 패스워드 복잡성 설정
# 양호 : 영문, 숫자, 특수문자를 조합하여 2종류 조합 시 10자리 이상, 3종류 이상 조합 시 8자리 이상의 패스워드가 설정된 경우
# 취약 : 영문, 숫자, 특수문자를 조합하지 않거나 2종류 조합 시 10자리 미만, 3종류 이상 조합 시 8자리 미만의 패스워드가 설정된 경우
U02(){
  PWQUALITY_Path=/etc/security/pwquality.conf
  sed -i "/minlen/ c\\minlen=8" ${PWQUALITY_Path}
  sed -i "/dcredit/ c\\dcredit=-1" ${PWQUALITY_Path}
  sed -i "/ucredit/ c\\ucredit=-1" ${PWQUALITY_Path}
  sed -i "/lcredit/ c\\lcredit=-1" ${PWQUALITY_Path}
  sed -i "/ocredit/ c\\ocredit=-1" ${PWQUALITY_Path}
}

# U-03. 계정 잠금 임계값 설정
# 양호 : 계정 잠금 임계값이 5 이하의 값으로 설정되어 있는 경우
# 취약 : 계정 잠금 임계값이 설정되어 있지 않거나, 5 이하의 값으로 설정되어 있지 않은 경우
U03(){
  SYSAUTH_Path=/etc/pam.d/system-auth
  PASSAUTH_Path=/etc/pam.d/password-auth

  ## system-auth 수정
  if ! grep -q 'auth        required      pam_tally2.so deny=3 unlock_time=600' "${SYSAUTH_Path}"; then
    sed -i '/auth        required      pam_env.so/a auth        required      pam_tally2.so deny=3 unlock_time=600' ${SYSAUTH_Path}
  fi

  ## password-auth 수정
  if ! grep -q 'account     required      pam_tally2.so deny=3 unlock_time=600' "${PASSAUTH_Path}"; then
    sed -i '/account     required      pam_unix.so/a account     required      pam_tally2.so deny=3 unlock_time=600' ${PASSAUTH_Path}
  fi
}

# U-04. 패스워드 최대 사용 기간 설정
# 양호 : 패스워드의 최대 사용기간이 90일 이내로 설정되어 있는 경우
# 취약 : 패스워드의 최대 사용기간이 없거나, 90일 이내로 설정되어 있지 않은 경우
U04(){
  LOGIN_Path=/etc/login.defs
  if [ "$(grep ^PASS_MAX_DAYS "${LOGIN_Path}" | awk '{print $2}')" -gt 90 ]; then
  sed -i "/^PASS_MAX_DAYS/ c\\PASS_MAX_DAYS 90" "${LOGIN_Path}"
  fi
}

# U-05. 패스워드 파일 보호
# 양호 : 쉐도우 패스워드를 사용하거나, 패스워드를 암호화하여 저장하는 경우
# 취약 : 쉐도우 패스워드를 사용하지 않고, 패스워드를 암호화하여 저장하지 않는 경우
U05 () {
  PASSWORD_Path=/etc/passwd
  if ! [ "$(grep root ${PASSWORD_Path} | awk -F: '{ print $2}')" = "x" ]; then
  pwconv
  fi
}

# 2. 파일 및 디렉토리 관리
# U-06. root 홈, 패스 디렉터리 권한 및 패스 설정
# 양호 : PATH 환경변수에 "."이 맨 앞이나 중간에 포함되지 않은 경우
# 취약 : PATH 환경변수에 "."이 맨 앞이나 중간에 포함된 경우
# NCP VM 기본값으로 양호 기준을 충족하여 미적용
U06(){
  echo ""
}

# U-07. 파일 및 디렉터리 소유자 설정
# 양호 : 소유자나 그룹이 존재하지 않는 파일 및 디렉터리가 없는 경우
# 취약 : 소유자나 그룹이 존재하지 않는 파일 및 디렉터리가 있는 경우
U07(){
  if [ -n "$(find /etc /tmp /bin /sbin \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2> /dev/null)" ]; then
    find /etc /tmp /bin /sbin \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2> /dev/null >> /root/U07_NO_OWNER_LIST.txt
  fi
}


# U-08. /etc/passwd 파일 소유자 및 권한 설정
# 양호 : /etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우
# 취약 : /etc/passwd 파일의 소유자가 root가 아니거나, 권한이 644 초과인 경우
U08 () {
  PASSWD_Path=/etc/passwd
  if [ -z "$(find ${PASSWD_Path} -perm 644)" ]; then
    chmod 644 ${PASSWD_Path}
  fi
  if [ -z "$(find ${PASSWD_Path} -user root)" ]; then
    chown root.root "${PASSWD_Path}"
  fi
}

# U-09. /etc/shadow 파일 소유자 및 권한 설정
# 양호 : /etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우
# 취약 : /etc/shadow 파일의 소유자가 root가 아니거나, 권한이 400 초과인 경우
U09 () {
  SHADOW_Path=/etc/shadow
  if [ -z "$(find ${SHADOW_Path} -perm 400)" ]; then
    chmod 400 ${SHADOW_Path}
  fi
  if [ -z "$(find ${SHADOW_Path} -user root)" ]; then
    chown root.root "${SHADOW_Path}"
  fi
}

# U-10. /etc/hosts 파일 소유자 및 권한 설정
# 양호 : /etc/hosts 파일의 소유자가 root이고, 권한이 644 이하인 경우
# 취약 : /etx/hosts 파일의 소유자가 root가 아니거나, 권한이 644 초과인 경우
U10 () {
  HOSTS_Path=/etc/hosts
  if [ -z "$(find ${HOSTS_Path} -perm 644)" ]; then
    chmod 644 ${HOSTS_Path}
  fi
  if [ -z "$(find ${HOSTS_Path} -user root)" ]; then
    chown root.root "${HOSTS_Path}"
  fi
}

# U-11. /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# 양호 : /etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 644 이하인 경우
# 취약 : /etc/(x)inetd.conf 파일의 소유자가 root가 아니거나, 권한이 644 초과인 경우
U11 () {
  XINETD_Path=/etc/xinetd.conf
  if [ -z "$(find ${XINETD_Path} -perm 644 > /dev/null 2>&1)" ]; then
    chmod 644 ${XINETD_Path}
  fi
  if [ -z "$(find ${XINETD_Path} -user root > /dev/null 2>&1)" ]; then
    chown root.root "${XINETD_Path}"
  fi
}

# U-12. /etc/(r)syslog.conf 파일 소유자 및 권한 설정
# 양호 : /etc/rsyslog.conf 파일의 소유자가 root이고, 권한이 644 이하인 경우
# 취약 : /etc/rsyslog.conf 파일의 소유자가 root가 아니거나, 권한이 644 초과인 경우
U12 () {
  RSYSLOG_Path=/etc/rsyslog.conf
  if [ -z "$(find ${RSYSLOG_Path} -perm 644 > /dev/null 2>&1)" ]; then
    chmod 644 ${RSYSLOG_Path}
  fi
  if [ -z "$(find ${RSYSLOG_Path} -user root > /dev/null 2>&1)" ]; then
    chown root.root "${RSYSLOG_Path}"
  fi
}

# U-13. /etc/services 파일 소유자 및 권한 설정
# 양호 : /etc/services 파일의 소유자가 root 이고, 권한이 644 이하인 경우
# 취약 : /etc/services 파일의 소유자가 root가 아니거나, 권한이 644 초과인 경우
U13 () {
  SERVICES_Path=/etc/services
  if [ -z "$(find ${SERVICES_Path} -perm 644 > /dev/null 2>&1)" ]; then
    chmod 644 ${SERVICES_Path}
  fi
  if [ -z "$(find ${SERVICES_Path} -user root > /dev/null 2>&1)" ]; then
    chown root.root "${SERVICES_Path}"
  fi
}

# U-14. SUID, SGID, sticky bit 설정 파일 점검
# SUID, SGID 권한이 제거될 파일 분류 작업 필요

# U-15. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
# 양호 : 사용자, 시스템 시작파일 및 환경 파일 소유자가 root 또는 해당 계정이고 권한이 644로 설정되어 있는 경우
# 취약 : 사용자, 시스템 시작파일 및 환경 파일 소유자가 root가 아니거나 권한이 644로 설정되어 있지 않은 경우
U15(){
  grep "home/" /etc/passwd | while read -r line ; do
    # /etc/passwd에서 정보 추출
    username="$(echo "${line}" | cut -d: -f1)"
    home_dir="$(echo "${line}" | cut -d: -f6)"

    # home Dir 정보 가져오기
    dir_info=$(ls -ld "${home_dir}")

    permissions=$(echo "${dir_info}" | awk '{print $1}')
    owner=$(echo "${dir_info}" | awk '{print $3}')
    group=$(echo "${dir_info}" | awk '{print $4}')

    if [ "${permissions}" != "drwx------" ]; then
      chmod 644 "${home_dir}"
    fi

    if [ "${owner}" != "${username}" ] || [ "${group}" != "${username}" ]; then
      chown "${username}"."${username}" "${home_dir}"
    fi
  done
}

# U-16. world writable 파일 점검
# 대상 파일이 너무 많은 관계로 보류

# U-17. $HOME/.rhosts, hosts.equiv 사용 금지
# NCP에서 제공하는 CentOS7.8 이미지에 /etc/hosts.equiv가 포함되어 있지 않아 제외

# U-18. 접속 IP 및 포트 제한
# VPN 기반 환경에서도 적용이 필요한지 검토 필요

# U-19. cron 파일 소유자 및 권한 설정
# 양호 : /etc/crontab 파일의 소유자가 root이고, 권한이 640 이하인 경우
# 취약 : /etc/crontab 파일의 소유자가 root가 아니거나, 권한이 640 초과인 경우
U19 () {
  CRONTAB_Path=/etc/crontab
  if [ -z "$(find ${CRONTAB_Path} -perm 640)" ] || [ -z "$(find ${CRONTAB_Path} -user root)" ]; then
    chmod 640 ${CRONTAB_Path}
    chown root.root ${CRONTAB_Path}
  fi
}

# 3. 서비스 관리
# U-20. Finger 서비스 비활성화
# 양호 : finger 서비스가 비활성화 되어 있는 경우
# 취약 : finger 서비스가 활성화 되어 있는 경우
# Base 이미지 내 /etc/xinetd.d 폴더 내 파일이 없음으로 제외

# U-21. ANONYMOUS FTP 비활성화
# 양호 : Anonymous FTP (익명 ftp) 접속을 차단한 경우
# 취약 : Anonymous FTP (익명 ftp) 접속을 차단하지 않은 경우
# Base 이미지 내 /etc/passwd ftp 계정, /etc/proftpd/, /etc/vsftpd 가 존재하지 않음으로 제외

# U-22. r 계열 서비스 비활성화
# Base 이미지 내 /etc/xinetd.d 폴더 내 파일이 없음으로 제외

# U-23. DoS 공격에 취약한 서비스 비활성화
# Base 이미지 내 /etc/xinetd.d 폴더 내 파일이 없음으로 제외

# U-24. NFS 서비스 비활성화
# 양호 : NFS 서비스 관련 데몬이 비활성화 되어 있는 경우
# 취약 : NFS 서비스 관련 데몬이 활성화 되어 있는 경우
U24(){
  if [ -n "$(pgrep -f 'nfs')" ]; then
    kill -9 "$(pgrep -f 'nfs')"
  fi
}

# U-25. NFS 접근통제
# Base 이미지 내 everymount, /etc/exports가 설정되어 있지 않기 때문에 제외

# U-26. automountd 제거
# 양호 : automount 서비스가 비활성화 되어 있는 경우
# 취약 : automount 서비스가 활성화 되어 있는 경우
U26(){
  if [ -n "$(pgrep -f 'automount')" ]; then
    kill -9 "$(pgrep -f 'automount')"
  fi
}

# U-27. RPC 서비스 확인
# Base 이미지 내 /etc/xinetd.d 폴더 내 파일이 없음으로 제외

# U-28. NIS, NIS+ 점검
# 양호 : NIS, NIS+ 서비스가 구동 중이지 않을 경우
# 취약 : NIS, NIS+ 서비스가 구동 중일 경우
U28 (){
  if [ -n "$(echo -e "ypserv\nypbind\nypxfrd\nrpc.yppasswdd\nrpc.ypupdated" | xargs -I {} pgrep {})" ]; then
    echo -e "ypserv\nypbind\nypxfrd\nrpc.yppasswdd\nrpc.ypupdated" | xargs -I {} kill -9 {}
  fi
}

# U-29. tftp, talk 서비스 비활성화
# Base 이미지 내 /etc/xinetd.d 폴더 내 파일이 없음으로 제외

# U-30. Sendmail 버전 점검
# Base 이미지 내 Sendmail이 설치되어 있지 않아 제외

# U-31. 스팸 메일 릴레이 제한
# Base 이미지 내 Sendmail이 설치되어 있지 않아 제외

# U-32. 일반사용자의 Sendmail 실행 방지
# Base 이미지 내 Sendmail이 설치되어 있지 않아 제외

# U-33. DNS 보안 버전 패치
# Base 이미지 내 Named가 설치되어 있지 않아 제외

# U-34. DNS ZoneTransfer 설정
# Base 이미지 내 Named가 설치되어 있지 않아 제외

# 4. 패치 및 로그관리
# U-35. 최신 보안패치 및 벤더 권고사항 적용
# 네이버 클라우드 Server(VM) 권고 사항으로 커널 업데이트 금지

# U-36. 로그의 정기적 검토 및 보고
# 네이버 클라우드 콘솔에서 Access Log 및 Security Log 수집하기 때문에 제외