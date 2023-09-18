#!/bin/bash

. ./function_v2.0.sh

# ===== 취약점 진단 리스트 =====
# 1. 계정 관리
SCAN-U01 (){
BAR
CODE "[U-01] root 계정 원격 접속 제한"
cat << EOF >> "${RESULT}"
양호 : 원격 터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우
취약 : 원격 터미널 서비스 사용 시 root 직접 접속을 허용한 경우
EOF
BAR

SECURETTY_Path=/etc/securetty
SSHD_Path=/etc/ssh/sshd_config
if grep -q '^pts' "${SECURETTY_Path}"; then
  WARN '/etc/securetty 파일 안에 pts/#이 존재합니다.'
else
  OK '/etc/securetty 파일 안에 pts/#이 존재하지 않습니다.'
fi

if [ "$(grep -E '^PermitRootLogin' "${SSHD_Path}")" != "PermitRootLogin no" ]; then
  WARN 'PermitRootLogin이 허용되어 있습니다.'
else
  OK 'PermitRootLogin이 차단되어 있습니다.'
fi

SPACE
}

# U-02. 패스워드 복잡성 설정'
SCAN-U02 () {
BAR
CODE "[U-02] 패스워드 복잡성 설정"
cat << EOF >> "${RESULT}"
양호 : 영문, 숫자, 특수문자를 조합하여 2종류 조합 시 10자리 이상, 3종류 이상 조합 시 8자리 이상의 패스워드가 설정된 경우
취약 : 영문, 숫자, 특수문자를 조합하지 않거나 2종류 조합 시 10자리 미만, 3종류 이상 조합 시 8자리 미만의 패스워드가 설정된 경우
EOF
BAR

PASSWD_Path=/etc/security/pwquality.conf

# minlen 검사
minlen=$(grep -E '^minlen' ${PASSWD_Path})
if [ -z "$minlen" ] || [ "$minlen" != "minlen=8" ]; then
  WARN "${PASSWD_Path}의 minlen 옵션이 올바르지 않습니다. [ 판정 기준 ] minlen=8"
else
  OK "${PASSWD_Path}의 minlen 옵션이 올바르게 설정되어 있습니다. $minlen"
fi

# dcredit 검사
dcredit=$(grep -E '^dcredit' ${PASSWD_Path})
if [ -z "$dcredit" ] || [ "$dcredit" != "dcredit=-1" ]; then
  WARN "${PASSWD_Path}의 dcredit 옵션이 올바르지 않습니다. [ 판정 기준 ] dcredit=-1"
else
  OK "${PASSWD_Path}의 dcredit 옵션이 올바르게 설정되어 있습니다. $dcredit"
fi

# ucredit 검사
ucredit=$(grep -E '^ucredit' ${PASSWD_Path})
if [ -z "$ucredit" ] || [ "$ucredit" != "ucredit=-1" ]; then
  WARN "${PASSWD_Path}의 ucredit 옵션이 올바르지 않습니다. [ 판정 기준 ] ucredit=-1"
else
  OK "${PASSWD_Path}의 ucredit 옵션이 올바르게 설정되어 있습니다. $ucredit"
fi

# lcredit 검사
lcredit=$(grep -E '^lcredit' ${PASSWD_Path})
if [ -z "$lcredit" ] || [ "$lcredit" != "lcredit=-1" ]; then
  WARN "${PASSWD_Path}의 lcredit 옵션이 올바르지 않습니다. [ 판정 기준 ] lcredit=-1"
else
  OK "${PASSWD_Path}의 lcredit 옵션이 올바르게 설정되어 있습니다. $lcredit"
fi

# ocredit 검사
ocredit=$(grep -E '^ocredit' ${PASSWD_Path})
if [ -z "$ocredit" ] || [ "$ocredit" != "ocredit=-1" ]; then
  WARN "${PASSWD_Path}의 ocredit 옵션이 올바르지 않습니다. [ 판정 기준 ] ocredit=-1"
else
  OK "${PASSWD_Path}의 ocredit 옵션이 올바르게 설정되어 있습니다. $ocredit"
fi

SPACE
}

# U-03. 계정 잠금 임계값 설정
SCAN-U03 () {
BAR
CODE "[U-03] 계정 잠금 임계값 설정"
cat << EOF >> "${RESULT}"
양호 : 계정 잠금 임계값이 5 이하의 값으로 설정되어 있는 경우
취약 : 계정 잠금 임계값이 설정되어 있지 않거나, 5 이하의 값으로 설정되어 있지 않은 경우
EOF
BAR

SYSTEMAUTH_Path=/etc/pam.d/system-auth
PASSWDAUTH_Path=/etc/pam.d/password-auth

if [ -z "$(< ${SYSTEMAUTH_Path} grep "auth" | grep "required" | grep pam_tally2)" ]; then
  WARN "${SYSTEMAUTH_Path} 내 pam_tally2 설정이 적용되어 있지 않습니다."
else
  OK "${SYSTEMAUTH_Path} 내 pam_tally2 설정이 정상입니다."
fi

if [ -z "$(< ${PASSWDAUTH_Path} grep "account" | grep "required" | grep pam_tally2)" ]; then
  WARN "${PASSWDAUTH_Path} 내 pam_tally2 설정이 적용되어 있지 않습니다."
else
  OK "${PASSWDAUTH_Path} 내 pam_tally2 설정이 정상입니다."
fi

SPACE
}

# U-04. 패스워드 최대 사용 기간 설정
SCAN-U04 () {
BAR
CODE "[U-04] 패스워드 최대 사용 기간 설정"
cat << EOF >> "${RESULT}"
양호 : 패스워드의 최대 사용기간이 90일 이내로 설정되어 있는 경우
취약 : 패스워드의 최대 사용기간이 없거나, 90일 이내로 설정되어 있지 않은 경우
EOF
BAR

LOGINDEF_Path=/etc/login.defs

if [ "$(< ${LOGINDEF_Path} grep -e ^PASS_MAX_DAYS | awk '{print $2}')" != 90 ]; then
  WARN "${LOGINDEF_Path} 내 PASS_MAX_DAYS가 90일로 설정되어 있지 않습니다."
else
  OK "${LOGINDEF_Path} 내 PASS_MAX_DAYS가 90일로 설정되어 있습니다."
fi

SPACE
}

# U-05. 패스워드 파일 보호
SCAN-U05 () {
BAR
CODE "[U-05] 패스워드 파일 보호"
cat << EOF >> "${RESULT}"
양호 : 쉐도우 패스워드를 사용하거나, 패스워드를 암호화하여 저장하는 경우
취약 : 쉐도우 패스워드를 사용하지 않고, 패스워드를 암호화하여 저장하지 않는 경우
EOF
BAR

PASSWD_Path=/etc/passwd

if [ "$(grep ^root ${PASSWD_Path} | awk -F: '{print $2}')" != 'x' ]; then
  WARN "${PASSWD_Path} 내 패스워드가 암호화되어 있지 않습니다."
else
  OK "${PASSWD_Path} 내 패스워드가 암호화되어 있습니다."
fi

SPACE
}

# 2. 파일 및 디렉토리 관리
# U-06. root 홈, 패스 디렉터리 권한 및 패스 설정
SCAN-U06 () {
BAR
CODE "[U-06] root 홈, 패스 디렉터리 권한 및 패스 설정"
cat << EOF >> "${RESULT}"
양호 : PATH 환경변수에 '.' 이 맨 앞이나 중간에 포함되지 않은 경우
취약 : PATH 환경변수에 '.' 이 맨 앞이나 중간에 포함된 경우
EOF
BAR

ROOTPROFILE_Path=/root/.bash_profile

if [ -n "$(grep -e '^PATH' ${ROOTPROFILE_Path} | grep "\.")" ]; then
  WARN "${ROOTPROFILE_Path} 내 PATH 경로에 '.' 이 포함되어 있습니다."
else
  OK "${ROOTPROFILE_Path} 내 PATH 경로에 '.' 이 포함되어 있지 않습니다."
fi

SPACE
}

# U-07. 파일 및 디렉터리 소유자 설정
SCAN-U07 () {
BAR
CODE "[U-07] 파일 및 디렉터리 소유자 설정"
cat << EOF >> "${RESULT}"
양호 : 소유자나 그룹이 존재하지 않는 파일 및 디렉터리가 없는 경우
취약 : 소유자나 그룹이 존재하지 않는 파일 및 데릭터리가 있는 경우
EOF
BAR

if [ -n "$(find /etc /tmp /bin /sbin \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2> /dev/null)" ]; then
  WARN "소유자나 그룹이 확인되지 않는 파일 및 데릭터리가 존재합니다."
else
  OK "소유자나 그룹이 확인되지 않는 파일 및 데릭터리가 없습니다."
fi

SPACE
}

# U-08. /etc/passwd 파일 소유자 및 권한 설정
SCAN-U08 () {
BAR
CODE "[U-08] /etc/passwd 파일 소유자 및 권한 설정"
cat << EOF >> "${RESULT}"
양호 : /etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우
취약 : /etc/passwd 파일의 소유자가 root가 아니거나, 권한이 644 초과인 경우
EOF
BAR

PASSWD_Path=/etc/passwd
if [ -z "$(find ${PASSWD_Path} -perm 644)" ]; then
  WARN "${PASSWD_Path}의 권한 수준이 644가 아닙니다."
else
  OK "${PASSWD_Path}의 권한 수준이 정상입니다."
fi

if [ -z "$(find ${PASSWD_Path} -user root)" ]; then
  WARN "${PASSWD_Path}의 소유자가 root가 아닙니다."
else
  OK "${PASSWD_Path}의 소유자가 root입니다."
fi

SPACE
}

# U-09. /etc/shadow 파일 소유자 및 권한 설정
SCAN-U09 () {
BAR
CODE "[U-09] /etc/shadow 파일 소유자 및 권한 설정"
cat << EOF >> "${RESULT}"
양호 : /etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우
취약 : /etc/shadow 파일의 소유자가 root가 아니거나, 권한이 400 초과인 경우
EOF
BAR

SHADOW_Path=/etc/shadow
if [ -z "$(find ${SHADOW_Path} -perm 400)" ]; then
  WARN "${SHADOW_Path}의 권한 수준이 400이 아닙니다."
else
  OK "${SHADOW_Path}의 권한 수준이 정상입니다."
fi

if [ -z "$(find ${SHADOW_Path} -user root)" ]; then
  WARN "${SHADOW_Path}의 소유자가 root가 아닙니다."
else
  OK "${SHADOW_Path}의 소유자가 root입니다."
fi

SPACE
}

# U-10. /etc/hosts 파일 소유자 및 권한 설정
SCAN-U10 () {
BAR
CODE "[U-10] /etc/hosts 파일 소유자 및 권한 설정"
cat << EOF >> "${RESULT}"
양호 : /etc/hosts 파일의 소유자가 root이고, 권한이 644 이하인 경우
취약 : /etc/hosts 파일의 소유자가 root가 아니거나, 권한이 644 초과인 경우
EOF
BAR

HOST_Path=/etc/hosts
if [ -z "$(find ${HOST_Path} -perm 644)" ]; then
  WARN "${HOST_Path}의 권한 수준이 644가 아닙니다."
else
  OK "${HOST_Path}의 권한 수준이 정상입니다."
fi

if [ -z "$(find ${HOST_Path} -user root)" ]; then
  WARN "${HOST_Path}의 소유자가 root가 아닙니다."
else
  OK "${HOST_Path}의 소유자가 root입니다."
fi

SPACE
}

# U-11. /etc/(x)inetd.conf 파일 소유자 및 권한 설정
SCAN-U11 () {
BAR
CODE "[U-11] /etc/(x)inetd.conf 파일 소유자 및 권한 설정"
cat << EOF >> "${RESULT}"
양호 : /etc/(x)inetd.conf 파일의 소유자가 root이고, 권한이 644 이하인 경우
취약 : /etc/(x)inetd.conf 파일의 소유자가 root가 아니거나, 권한이 644 초과인 경우
EOF
BAR

XINETD_Path=/etc/xinetd.conf
if [ -f "${XINETD_Path}" ]; then
  if [ -z "$(find ${XINETD_Path} -perm 644 > /dev/null 2>&1)" ]; then
    WARN "${XINETD_Path}의 권한 수준이 644가 아닙니다."
  else
    OK "${XINETD_Path}의 권한 수준이 정상입니다."
  fi

  if [ -z "$(find ${XINETD_Path} -user root /dev/null 2>&1)" ]; then
    WARN "${XINETD_Path}의 소유자가 root가 아닙니다."
  else
    OK "${XINETD_Path}의 소유자가 root입니다."
  fi
else
  OK "${XINETD_Path} 파일이 존재하지 않습니다."
fi

SPACE
}

# U-12. /etc/(r)syslog.conf 파일 소유자 및 권한 설정
SCAN-U12 () {
BAR
CODE "[U-12] /etc/sysconfig/rsyslog 파일 소유자 및 권한 설정"
cat << EOF >> "${RESULT}"
양호 : /etc/sysconfig/rsyslog 파일의 소유자가 root이고, 권한이 644 이하인 경우
취약 : /etc/sysconfig/rsyslog 파일의 소유자가 root가 아니거나, 권한이 644 초과인 경우
EOF
BAR

SYSLOG_Path=/etc/sysconfig/rsyslog
if [ -z "$(find ${SYSLOG_Path} -perm 644)" ]; then
  WARN "${SYSLOG_Path}의 권한 수준이 644가 아닙니다."
else
  OK "${SYSLOG_Path}의 권한 수준이 정상입니다."
fi

if [ -z "$(find ${SYSLOG_Path} -user root)" ]; then
  WARN "${SYSLOG_Path}의 소유자가 root가 아닙니다."
else
  OK "${SYSLOG_Path}의 소유자가 root입니다."
fi

SPACE
}

# U-13. /etc/services 파일 소유자 및 권한 설정
SCAN-U13 () {
BAR
CODE "[U-13] /etc/services 파일 소유자 및 권한 설정"
cat << EOF >> "${RESULT}"
양호 : /etc/services 파일의 소유자가 root이고, 권한이 644 이하인 경우
취약 : /etc/services 파일의 소유자가 root가 아니거나, 권한이 644 초과인 경우
EOF
BAR

SERVICES_Path=/etc/services
if [ -z "$(find ${SERVICES_Path} -perm 644)" ]; then
  WARN "${SERVICES_Path}의 권한 수준이 644가 아닙니다."
else
  OK "${SERVICES_Path}의 권한 수준이 정상입니다."
fi

if [ -z "$(find ${SERVICES_Path} -user root)" ]; then
  WARN "${SERVICES_Path}의 소유자가 root가 아닙니다."
else
  OK "${SERVICES_Path}의 소유자가 root입니다."
fi

SPACE
}

# U-14. SUID, SGID, sticky bit 설정 파일 점검
SCAN-U14 () {
BAR
CODE "[U-14] SUID, SGID, sticky bit 설정 파일 점검"
cat << EOF >> "${RESULT}"
양호 : 주요 실행파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않은 경우
취약 : 주요 실행파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있는 경우
EOF
BAR

if [ -n "$(find / -xdev -user root -type f \( -perm -04000 -o -perm -02000 \) -exec ls -al {} \;)" ]; then
  WARN "SUID와 SGID 설정이 부여되어 있는 실행파일이 존재합니다."
else
  OK "SUID와 SGID 설정이 부여되어 있는 실행파일이 존재하지 않습니다."
fi

SPACE
}

# U-15. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정
SCAN-U15 () {
BAR
CODE "[U-15] 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정"
cat << EOF >> "${RESULT}"
양호 : 사용자, 시스템 시작파일 및 환경 파일 소유자가 root 또는 해당 계정이고 권한이 644로 설정되어 있는 경우
취약 : 사용자, 시스템 시작파일 및 환경 파일 소유자가 root 또는 해당 계정이 아니거나 권한이 644로 설정되어 있지 않은 경우
EOF
BAR

grep "home/" /etc/passwd | while read -r line ; do
  # /etc/passwd에서 정보 추출
  username="$(echo "${line}" | cut -d: -f1)"
  home_dir="$(echo "${line}" | cut -d: -f6)"

  # home Dir 정보 가져오기
  dir_info=$(ls -ld "${home_dir}")

  permissions=$(echo "${dir_info}" | awk '{print $1}')
  owner=$(echo "${dir_info}" | awk '{print $3}')
  group=$(echo "${dir_info}" | awk '{print $4}')

#  echo "User: ${username}"
#  echo "Home Directory: ${home_dir}"
#  echo "Permissions: ${permissions}"
#  echo "Owner: ${owner}"
#  echo "Group: ${group}"

  if [ "${permissions}" != "drwx------" ]; then
    WARN "${home_dir}의 접근권한이 올바르지 않습니다."
  else
    OK "${home_dir}의 접근권한이 올바르게 부여되어 있습니다."
  fi

  if [ "${owner}" != "${username}" ] || [ "${group}" != "${username}" ]; then
    WARN "${home_dir}의 소유권한이 ${username}에게 할당되어 있지 않습니다.."
  else
    OK "${home_dir}의 소유권한이 ${username}에게 할당되어 있습니다."
  fi
done

SPACE
}

# U-16. world writable 파일 점검
SCAN-U16 () {
BAR
CODE "[U-16] world writable 파일 점검"
cat << EOF >> "${RESULT}"
양호 : world writable 파일이 존재하지 않거나, 존재 시 설정 이유를 확인하고 있는 경우
취약 : world writable 파일이 존재하나 해당 설정 이유를 확인하고 있지 않는 경우
EOF
BAR

if find / -type f -perm -2 -exec ls -l {} \; 2>/dev/null | grep -E -q -v '/proc/|/sys/fs/cgroup'; then
  WARN "world writable 파일이 존재합니다."
else
  OK "world writable 파일이 존재하지 않습니다."
fi

SPACE
}

# U-17. $HOME/.rhosts, hosts.equiv 사용 금지
SCAN-U17 () {
BAR
CODE "[U-17] world writable 파일 점검"
cat << EOF >> "${RESULT}"
양호 : login, shell, exec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우
      - /etc/hosts.equiv 및 \${HOME}/.rhosts 파일 소유자가 root 또는, 해당 계정인 경우
      - /etc/hosts.equiv 및 \${HOME}/.rhosts 파일 권한이 600 이하인 경우
      - /etc/hosts.equiv 및 \${HOME}/.rhosts 설정에 '+' 설정이 없는 경우
      - /etc/hosts.equiv 파일 또는 .rhosts 파일이 존재하지 않을 경우
취약 : Anonymous FTP (익명 ftp) 접속을 차단하지 않은 경우
      - /etc/hosts.equiv 및 \${HOME}/.rhosts 파일 소유자가 root 또는 해당 계정이 아닌 경우
      - /etc/hosts.equiv 및 \${HOME}/.rhosts 파일 권한이 600 초과인 경우
      - /etc/hosts.equiv 및 \${HOME}/.rhosts 설정에 '+' 설정이 있는 경우
      - /etc/hosts.equiv 파일 또는 .rhosts 파일이 존재하는 경우
EOF
BAR

EQUIV_Path=/etc/hosts.equiv
RHOSTS_Path=${HOME}/.rhosts
if [ -f "${EQUIV_Path}" ]; then
  if [ -z "$(find ${EQUIV_Path} -perm 600)" ] || [ -z "$(find ${EQUIV_Path} -user root)" ]; then
    WARN "${EQUIV_Path}의 소유자가 root가 아니거나 권한이 600을 초과합니다."
  else
    OK "${EQUIV_Path}의 소유자와 권한이 정상입니다."
  fi
else
  OK "${EQUIV_Path} 파일이 존재하지 않습니다."
fi

if [ -f "${RHOSTS_Path}" ]; then
  if [ -z "$(find "${RHOSTS_Path}" -perm 600)" ] || [ -z "$(find "${RHOSTS_Path}" -user root)" ]; then
    WARN "${RHOSTS_Path}의 소유자가 root가 아니거나 권한이 600을 초과합니다."
  else
    OK "${RHOSTS_Path}의 소유자와 권한이 정상입니다."
  fi
else
  OK "${RHOSTS_Path} 파일이 존재하지 않습니다."
fi

SPACE
}

# U-18. 접속 IP 및 포트 제한
# 검토 필요

# U-19. cron 파일 소유자 및 권한 설정
SCAN-U19 () {
BAR
CODE "[U-19] cron 파일 소유자 및 권한 설정"
cat << EOF >> "${RESULT}"
양호 : /etc/crontab 파일의 소유자가 root이고, 권한이 640 이하인 경우
취약 : /etc/crontab 파일의 소유자가 root가 아니거나, 권한이 640 초과인 경우
EOF
BAR

CRONTAB_Path=/etc/crontab

if [ -z "$(find ${CRONTAB_Path} -perm 640)" ] || [ -z "$(find ${CRONTAB_Path} -user root)" ]; then
  WARN "/etc/crontab 파일의 소유자가 root가 아니거나 권한이 640 초과입니다."
else
  OK "/etc/crontab 파일의 소유자와 권한이 정상입니다."
fi

SPACE
}

# 3. 서비스 관리
# U-20. Finger 서비스 비활성화
SCAN-U20 () {
BAR
CODE "[U-20] Finger 서비스 비활성화"
cat << EOF >> "${RESULT}"
양호 : finger 서비스가 비활성화 되어 있는 경우
취약 : finger 서비스가 활성화 되어 있는 경우
EOF
BAR

FINGER_Path=/etc/xinetd.d/finger
if [ -f "${FINGER_Path}" ]; then
  if awk '/disable/ && /yes/' "${FINGER_Path}" > /dev/null 2>&1; then
    OK "Finger 서비스가 비활성화되어 있습니다."
  else
    WARN "Finger 서비스가 활성화되어 있습니다."
  fi
else
  OK "Finger 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

SPACE
}

# U-21. ANONYMOUS FTP 비활성화
SCAN-U21 () {
BAR
CODE "[U-21] ANONYMOUS FTP 비활성"
cat << EOF >> "${RESULT}"
양호 : Anonymous FTP (익명 ftp) 접속을 차단한 경우
취약 : Anonymous FTP (익명 ftp) 접속을 차단하지 않은 경우
EOF
BAR

# Default FTP 서비스 확인
if grep -E 'ftp' /etc/passwd > /dev/null 2>&1; then
  WARN "Default FTP 서비스가 활성화 상태입니다."
else
  OK "Default FTP 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

# ProFTP 서비스 확인
if [ -f /etc/proftpd/proftpd.conf ]; then
  if awk '/^UserAlias/ && /anonymous/ && /ftp/' > /dev/null 2>&1; then
    WARN "ProFTP 서비스가 활성화 상태입니다."
  else
    OK "ProFTP 서비스가 설치되어 있으나 비활성화 상태입니다."
  fi
else
  OK "ProFTP 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

# vsFTP 서비스 확인
if [ -f /etc/vsftpd/vsftpd.conf ]; then
  if awk '/^anonymous_enable/ && /Yes/ || /yes/'; then
    WARN "vsFTP 서비스가 활성화 상태입니다."
  else
    OK "vsFTP 서비스가 설치되어 있으나 비활성화 상태입니다."
  fi
else
  OK "vsFTP 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

SPACE
}

# U-22. r 계열 서비스 비활성화
SCAN-U22 () {
BAR
CODE "[U-22] r 계열 서비스 비활성화"
cat << EOF >> "${RESULT}"
양호 : r 계열 서비스(rlogin, rsh, rexec)가 비활성화 되어 있는 경우
취약 : r 계열 서비스(rlogin, rsh, rexec)가 활성화 되어 있는 경우
EOF
BAR

RSH_Path=/etc/xinetd.d/rsh
RLOGIN_Path=/etc/xinetd.d/rlogin
REXEC_Path=/etc/xinetd.d/rexec

if [ -f "${RSH_Path}" ]; then
  if awk '/disable/ && /yes/' "${RSH_Path}" > /dev/null 2>&1; then
    OK "rsh 서비스가 비활성화되어 있습니다."
  else
    WARN "rsh 서비스가 활성화되어 있습니다."
  fi
else
  OK "rsh 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

if [ -f "${RLOGIN_Path}" ]; then
  if awk '/disable/ && /yes/' "${RLOGIN_Path}" > /dev/null 2>&1; then
    OK "rlogin 서비스가 비활성화되어 있습니다."
  else
    WARN "rlogin 서비스가 활성화되어 있습니다."
  fi
else
  OK "rlogin 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

if [ -f "${REXEC_Path}" ]; then
  if awk '/disable/ && /yes/' "${REXEC_Path}" > /dev/null 2>&1; then
    OK "rexec 서비스가 비활성화되어 있습니다."
  else
    WARN "rexec 서비스가 활성화되어 있습니다."
  fi
else
  OK "rexec 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

SPACE
}

# U-23. DoS 공격에 취약한 서비스 비활성화
SCAN-U23 () {
BAR
CODE "[U-23] DoS 공격에 취약한 서비스 비활성화"
cat << EOF >> "${RESULT}"
양호 : DoS 공격에 취약한 echo, discard, daytime, chargen 서비스가 비활성화 되어 있는 경우
취약 : DoS 공격에 취약한 echo, discard, daytime, chargen 서비스가 활성화 되어 있는 경우
EOF
BAR

ECHO_Path=/etc/xinetd.d/echo
DISCARD_Path=/etc/xinetd.d/discard
DAYTIME_Path=/etc/xinetd.d/daytime
CHARGEN_Path=/etc/xinetd.d/chargen

if [ -f "${ECHO_Path}" ]; then
  if awk '/disable/ && /yes/' "${ECHO_Path}" > /dev/null 2>&1; then
    OK "echo 서비스가 비활성화되어 있습니다."
  else
    WARN "echo 서비스가 활성화되어 있습니다."
  fi
else
  OK "echo 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

if [ -f "${DISCARD_Path}" ]; then
  if awk '/disable/ && /yes/' "${DISCARD_Path}" > /dev/null 2>&1; then
    OK "discard 서비스가 비활성화되어 있습니다."
  else
    WARN "discard 서비스가 활성화되어 있습니다."
  fi
else
  OK "discard 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

if [ -f "${DAYTIME_Path}" ]; then
  if awk '/disable/ && /yes/' "${DAYTIME_Path}" > /dev/null 2>&1; then
    OK "daytime 서비스가 비활성화되어 있습니다."
  else
    WARN "daytime 서비스가 활성화되어 있습니다."
  fi
else
  OK "daytime 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

if [ -f "${CHARGEN_Path}" ]; then
  if awk '/disable/ && /yes/' "${CHARGEN_Path}" > /dev/null 2>&1; then
    OK "chargen 서비스가 비활성화되어 있습니다."
  else
    WARN "chargen 서비스가 활성화되어 있습니다."
  fi
else
  OK "chargen 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

SPACE
}

# U-24. NFS 서비스 비활성화
SCAN-U24 () {
BAR
CODE "[U-24] NFS 서비스 비활성화"
cat << EOF >> "${RESULT}"
양호 : NFS 서비스 관련 데몬이 비활성화 되어 있는 경우
취약 : NFS 서비스 관련 데몬이 활성화 되어 있는 경우
EOF
BAR

if [ -n "$(pgrep -f 'nfsd')" ]; then
  WARN "NFS 서비스가 현재 활성화 되어 있습니다."
else
  OK "NFS 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

SPACE
}

# U-25. NFS 접근통제
SCAN-U25 () {
BAR
CODE "[U-25] NFS 접근통제"
cat << EOF >> "${RESULT}"
양호 : NFS 서비스 사용 시 everyone 공유를 제한한 경우
취약 : NFS 서비스 사용 시 everyone 공유를 제한하지 않은 경우
EOF
BAR

EXPORTS_Path=/etc/exports

if showmount -e hostname > /dev/null 2>&1; then
  if grep -E -q '*' "${EXPORTS_Path}"; then
    WARN "everyone으로 마운트 된 NFS 서비스가 존재합니다."
  else
    OK "everyone으로 마운트 된 NFS 서비스가 없습니다."
  fi
else
  OK "NFS 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

SPACE
}

# U-26. automountd 제거
SCAN-U26 () {
BAR
CODE "[U-26] automountd"
cat << EOF >> "${RESULT}"
양호 : automount 서비스가 비활성화 되어 있는 경우
취약 : automount 서비스가 활성화 되어 있는 경우
EOF
BAR

if [ -n "$(pgrep -f 'automount')" ]; then
  WARN "automount 서비스가 활성화되어 있습니다."
else
  OK "automount 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

SPACE
}

# U-27. RPC 서비스 확인
SCAN-U27 () {
BAR
CODE "[U-27] RPC 서비스 확인"
cat << EOF >> "${RESULT}"
양호 : 불필요한 RPC 서비스가 비활성화 되어 있는 경우
취약 : 불필요한 RPC 서비스가 활성화 되어 있는 경우
EOF
BAR

RSTATD_Path=/etc/xinetd.d/rstatd

if [ -f "${RSTATD_Path}" ]; then
  if awk '/disable/ && /yes/' "${RSTATD_Path}" > /dev/null 2>&1; then
    OK "불필요한 RPC 서비스가 비활성화되어 있습니다."
  else
    WARN "불필요한 RPC 서비스가 활성화되어 있습니다."
  fi
else
  OK "RPC 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

SPACE
}

# U-28. NIS, NIS+ 점검
SCAN-U28 () {
BAR
CODE "[U-28] NIS, NIS+ 점검"
cat << EOF >> "${RESULT}"
양호 : NIS, NIS+ 서비스가 구동 중이지 않을 경우
취약 : NIS, NIS+ 서비스가 구동 중일 경우
EOF
BAR

if [ -n "$(echo -e "ypserv\nypbind\nypxfrd\nrpc.yppasswdd\nrpc.ypupdated" | xargs -I {} pgrep {})" ]; then
  WARN "NIS 또는 NIS+가 구동 중입니다."
else
  OK "NIS 또는 NIS+ 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

SPACE
}

# U-29. tftp, talk 서비스 비활성화
SCAN-U29 () {
BAR
CODE "[U-29] tftp, talk 서비스 비활성화"
cat << EOF >> "${RESULT}"
양호 : tftp, talk 서비스가 비활성화 되어 있는 경우
취약 : tftp, talk 서비스가 활성화 되어 있는 경우
EOF
BAR

TFTP_Path=/etc/xinetd.d/tftp
TALK_Path=/etc/xinetd.d/talk
NTALK_Path=/etc/xinetd.d/talk

if [ -f "${TFTP_Path}" ]; then
  if awk '/disable/ && /yes/' "${TFTP_Path}" > /dev/null 2>&1; then
    OK "tftp 서비스가 비활성화 상태입니다."
  else
    WARN "tftp 서비스가 활성화 상태입니다."
  fi
else
  OK "tftp 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

if [ -f "${TALK_Path}" ]; then
  if awk '/disable/ && /yes/' "${TALK_Path}" > /dev/null 2>&1; then
    OK "talk 서비스가 비활성화 상태입니다."
  else
    WARN "talk 서비스가 활성화 상태입니다."
  fi
else
  OK "talk 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

if [ -f "${NTALK_Path}" ]; then
  if awk '/disable/ && /yes/' "${NTALK_Path}" > /dev/null 2>&1; then
    OK "ntalk 서비스가 비활성화 상태입니다."
  else
    WARN "ntalk 서비스가 활성화 상태입니다."
  fi
else
  OK "ntalk 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

SPACE
}

# U-30. Sendmail 버전 점검
SCAN-U30 () {
BAR
CODE "[U-30] Sendmail 버전 점검"
cat << EOF >> "${RESULT}"
양호 : Sendmail 버전을 정기적으로 점검하고, 최신 버전 패치를 했을 경우
취약 : Sendmail 버전을 정기적으로 점검하지 않거나, 최신 버전 패치가 되어 있지 않은 경우
EOF
BAR

# 최신 버전 : https://www.cvedetails.com/version-list/31/45/1/Sendmail-Sendmail.html
LATEST_VERSION=9.2.20
CURRENT_VERSION=$(sendmail -d0.1 < /dev/null 2>/dev/null | awk '/Version/ {print $2}')
if pgrep sendmail > /dev/null; then
  if [[ -n "${CURRENT_VERSION}" ]]; then
    IFS="." read -ra LATEST_PARTS <<< "${LATEST_VERSION}"
    IFS="." read -ra CURRENT_PARTS <<< "${CURRENT_VERSION}"

    for i in 0 1 2; do
      if [[ "${LATEST_PARTS[$i]}" -gt "${CURRENT_PARTS[$i]}" ]]; then
        WARN "Sendmail 서비스가 최신 버전이 아닙니다. [기준 : ${LATEST_VERSION}]"
        exit 1
      elif [[ "${LATEST_PARTS[$i]}" -lt "${CURRENT_PARTS[$i]}" ]]; then
        OK "Sendmail 서비스가 최신 버전입니다. [기준 : ${LATEST_VERSION}]"
        exit 0
      fi
    done
  else
    WARN "Sendmail 서비스가 설치되어 있으나 버전 정보를 가져올 수 없습니다."
  fi
else
  OK "Sendmail 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

SPACE
}

# U-31. 스팸 메일 릴레이 제한
SCAN-U31 () {
BAR
CODE "[U-31] 스팸 메일 릴레이 제한"
cat << EOF >> "${RESULT}"
양호 : SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있는 경우
취약 : SMTP 서비스를 사용하며 릴레이 제한이 설정되어 있지 않은 경우
EOF
BAR

if pgrep sendmail > /dev/null 2>&1; then
  if [ -z "$(awk '/^R$*/ && /Relaying denied/' /etc/mail/sendmail.cf > /dev/null 2>&1)" ]; then
    WARN "Sendmail 릴레이 제한이 설정되어 있지 않습니다."
  else
    OK "Sendmail 릴레이 제한이 설정되어 있습니다."
  fi
else
  OK "Sendmail 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

SPACE
}

# U-32. 일반사용자의 Sendmail 실행 방지
SCAN-U32 () {
BAR
CODE "[U-32] 일반사용자의 Sendmail 실행 방지"
cat << EOF >> "${RESULT}"
양호 : SMTP 서비스 미사용 또는, 일반 사용자의 Sendmail 실행 방지가 설정된 경우
취약 : SMTP 서비스 사용 또는, 일반 사용자의 Sendmail 실행 방지가 설정되지 않은 경우
EOF
BAR

if pgrep sendmail > /dev/null 2>&1; then
  if [ -z "$(awk '/^O PrivacyOptions/ && /restrictqrun/' /etc/mail/sendmail.cf > /dev/null 2>&1)" ]; then
    WARN "일반 사용자의 Sendmail 실행 방지가 설정되지 않았습니다."
  else
    OK "일반 사용자의 Sendmail 실행 방지가 설정되어 있습니다."
  fi
else
  OK "Sendmail 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

SPACE
}

# U-33. DNS 보안 버전 패치
SCAN-U33 () {
BAR
CODE "[U-33] DNS 보안 버전 패치"
cat << EOF >> "${RESULT}"
양호 : DNS 서비스를 사용하지 않거나 주기적으로 패치를 관리하고 있는 경우
취약 : DNS 서비스를 사용하며, 주기적으로 패치를 관리하고 있지 않은 경우
EOF
BAR

# 최신 버전 : https://www.isc.org/bind/
LATEST_VERSION=9.18.18
CURRENT_VERSION=$(named -v < /dev/null 2>/dev/null | awk '{print $2}' | awk -F- '{print $1}')
if pgrep named > /dev/null; then
  if [[ -n "${CURRENT_VERSION}" ]]; then
    IFS="." read -ra LATEST_PARTS <<< "${LATEST_VERSION}"
    IFS="." read -ra CURRENT_PARTS <<< "${CURRENT_VERSION}"

    for i in 0 1 2; do
      if [[ "${LATEST_PARTS[$i]}" -gt "${CURRENT_PARTS[$i]}" ]]; then
        WARN "Bind(named) 서비스가 최신 버전이 아닙니다. [기준 : ${LATEST_VERSION}]"
        exit 1
      elif [[ "${LATEST_PARTS[$i]}" -lt "${CURRENT_PARTS[$i]}" ]]; then
        OK "Bind(named) 서비스가 최신 버전입니다. [기준 : ${LATEST_VERSION}]"
        exit 0
      fi
    done
  else
    WARN "Bind(named) 서비스가 설치되어 있으나 버전 정보를 가져올 수 없습니다."
  fi
else
  OK "Bind(named) 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

SPACE
}

# U-34. DNS ZoneTransfer 설정
SCAN-U34 () {
BAR
CODE "[U-34] DNS ZoneTransfer 설정"
cat << EOF >> "${RESULT}"
양호 : DNS 서비스 미사용 또는, Zone Transfer를 허가된 사용자에게만 허용한 경우
취약 : DNS 서비스 사용하며 Zone Transfer를 모든 사용자에게 허용한 경우
EOF
BAR

NAMED_Path=/etc/named.conf

if pgrep named > /dev/null 2>&1; then
  if grep -E -q -v "allow-transfer" ${NAMED_Path}; then
    WARN "BIND(named) 서비스에 Zone Transfer 설정이 적용되어 있지 않습니다."
  else
    OK "BIND(named) 서비스에 Zone Transfer 설정이 적용되어 있습니다."
  fi
else
  OK "Bind(named) 서비스가 설치되어 있지 않거나 실행 중이지 않습니다."
fi

SPACE
}