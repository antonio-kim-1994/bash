#!/bin/bash
# 사용자 추가 및 비밀번호 설정
USERNAME="test"
PASSWD="test1234"

useradd "${USERNAME}"
echo "${USERNAME}:${PASSWD}" | chpasswd

### /etc/sudoers
#1. user 권한 추가
# sed -i '/<탐색구간>/a <치환구간>' <파일경로>
sed -i "/^root\tALL/a ${USERNAME}\tALL=(ALL:ALL) ALL" /etc/sudoers


### /etc/profile
# 1. umask 변경
echo 'umask 0022' >> /etc/profile

# 2. TMOUT 변경
sed -i '/TMOUT=/ c\TMOUT=800' /etc/profile

# 3. export TMOUT
echo "readonly TMOUT" >> /etc/profile
echo "export TMOUT" >> /etc/profile
source /etc/profile

### /etc/pam.d/common-password
sed -i '/try_first_pass sha512/s/$/ minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password


### /etc/login.defs
# 1. Login Option 수정
sed -i "/^PASS_MAX_DAYS/ c\\PASS_MAX_DAYS\t90" /etc/login.defs
sed -i "/PASS_MIN_LEN/ c\\PASS_MIN_LEN\t8" /etc/login.defs
sed -i "/LOG_OK_LOGINS/ c\\LOG_OK_LOGINS\tyes" /etc/login.defs
sed -i "/LOGIN_RETRIES/ c\\LOGIN_RETRIES\t3" /etc/login.defs
sed -i "/LOGIN_TIMEOUT/ c\\LOGIN_TIMEOUT\t20" /etc/login.defs

### SU 명령 사용가능 그룹 제한 설정
chmod 4750 /bin/su
chown root.sudo /bin/su
sed -i "/^sudo/ s/$/root,${USERNAME}/" /etc/group

#### C 컴파일러 권한 추가
echo "gcc:x:800:root" >> /etc/group
chgrp gcc /usr/bin/gcc
chmod 750 /usr/bin/gcc

#### Cron 사용 제한
chmod 640 -R /etc/cron*
chmod 640 /etc/at.*

### /etc/ssh/sshd_config
function sshdConfig {
    sed -i -r "/$1/ c\\$2" /etc/ssh/sshd_config
}

# 1. Printmotd 활성화
sshdConfig PrintMotd "PrintMotd yes"
# 2. Banner 활성화
sshdConfig Banner "Banner /etc/issue.net"
# 3. Root 로그인 차단
sshdConfig "^(#?PermitRootLogin)" "PermitRootLogin no"
# 4. 로그인 시도 횟수 조정
sshdConfig MaxAuthTries "MaxAuthTries 3"

# 수정 사항 적용
sudo systemctl restart sshd

### crontab 등록
(crontab -l 2>/dev/null; echo "00 01 * * * su - root /usr/bin/rdate -s time.bora.net && /sbin/hwclock -w") | crontab -

## rc.local 소유자 권한 변경
chown root /etc/rc.local
chmod 600 /etc/rc.local