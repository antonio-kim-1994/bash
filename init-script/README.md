# 보안 취약점 진단 가이드

<div align="center">

![Static Badge](https://img.shields.io/badge/CentOS_7.8-14213d?style=flat&logo=centos)
![Static Badge](https://img.shields.io/badge/Ubuntu_18.04-f4a261?style=flat&logo=ubuntu)

</div>

## 보안 기준표
> 취약점 진단 기준표는 [`CSAP_클라우드_취약점_점검_가이드-Linux.pdf`](./CSAP_클라우드_취약점_점검_가이드-Linux.pdf) 를 참고한다.

<table>
    <tr>
        <td align="center" style="background-color: #e5e5e5"><b>구분</b></td>
        <td align="center" style="background-color: #e5e5e5"><b>진단항목</b></td>
    </tr>
    <tr>
        <td rowspan="5">가. 계정 관리</td>
        <td>1. root 계정 원격 접속 설정 제한</td>
    </tr>
    <tr>
        <td>2. 패스워드 복잡성 설정</td>
    </tr>
    <tr>
        <td>3. 계정 잠금 임계값 설정</td>
    </tr>
    <tr>
        <td>4. 패스워드 최대 사용 기간 설정</td>
    </tr>
    <tr>
        <td>5. 패스워드 파일 보호</td>
    </tr>
    <tr>
        <td rowspan="14">나. 파일 및 디렉토리 관리</td>
        <td>1. root 홈, 패스 디렉터리 권한 및 패스 설정</td>
    </tr>
    <tr>
        <td>2. 파일 및 디렉터리 소유자 설정</td>
    </tr>
    <tr>
        <td>3. /etc/passwd 파일 소유자 및 권한 설정</td>
    </tr>
    <tr>
        <td>4. /etc/shadow 파일 소유자 및 권한 설정</td>
    </tr>
    <tr>
        <td>5. /etc/hosts 파일 소유자 및 권한 설정</td>
    </tr>
    <tr>
        <td>6. /etc/(x)inetd.conf 파일 소유자 및 권한 설정</td>
    </tr>
    <tr>
        <td>7. /etc/syslog.conf 파일 소유자 및 권한 설정</td>
    </tr>
    <tr>
        <td>8. /etc/services 파일 소유자 및 권한 설정</td>
    </tr>
    <tr>
        <td>9. SUID, SGID, Sticky bit 설정 파일 점검</td>
    </tr>
    <tr>
        <td>10. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정</td>
    </tr>
    <tr>
        <td>11. world writable 파일 점검</td>
    </tr>
    <tr>
        <td>12. $HOME/.rhosts, hosts.equiv 사용 금지</td>
    </tr>
    <tr>
        <td>13. 접속 IP 및 포트 제한</td>
    </tr>
    <tr>
        <td>14. cron 파일 소유자 및 권한 설정</td>
    </tr>
    <tr>
        <td rowspan="15">다. 서비스 관리</td>
        <td>1. Finger 서비스 비활성화</td>
    </tr>
    <tr>
        <td>2. Anonymous FTP 비활성화</td>
    </tr>
    <tr>
        <td>3. r 계열 서비스 비활성화</td>
    </tr>
    <tr>
        <td>4. Dos 공격에 취약한 서비스 비활성화</td>
    </tr>
    <tr>
        <td>5. NFS 서비스 비활성화</td>
    </tr>
    <tr>
        <td>6. NFS 접근 통제</td>
    </tr>
    <tr>
        <td>7. automountd 제거</td>
    </tr>
    <tr>
        <td>8. RPC 서비스 확인</td>
    </tr>
    <tr>
        <td>9. NIS, NIS+ 점검</td>
    </tr>
    <tr>
        <td>10. tftp, talk 서비스 비활성화</td>
    </tr>
    <tr>
        <td>11. Sendmail 버전 점검</td>
    </tr>
    <tr>
        <td>12. 스팸 메일 릴레이 제한</td>
    </tr>
    <tr>
        <td>13. 일반사용자의 Sendmail 실행 방지</td>
    </tr>
    <tr>
        <td>14. DNS 보안 버전 패치</td>
    </tr>
    <tr>
        <td>15. DNS ZoneTransfer 설정</td>
    </tr>
    <tr>
        <td rowspan="2">라. 패치 및 로그 관리</td>
        <td>1. 최신 보안패치 및 벤더 권고사항 적용</td>
    </tr>
    <tr>
        <td>2. 로그의 정기적 검토 및 보고</td>
    </tr>
</table>

### 참고 링크
- [네이버 블로그 - 타쿠대디](https://blog.naver.com/takudaddy/222220602092)
- [![Static Badge](https://img.shields.io/badge/newbieh4cker/centos_vuln_check_script-14213d?style=flat&logo=github)](https://github.com/newbieh4cker/centos_vuln_check_script/blob/master/linux_vuln_check_script.sh)