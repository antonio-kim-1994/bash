#!/bin/bash
login_script(){
  cat > /etc/profile.d/login_script.sh << 'EOF'
  USED_MEM=$(free -m | grep Mem | awk '{print $3}')
  TOTAL_MEM=$(free -m | grep Mem | awk '{print $2}')
  MEM_USAGE=$(awk "BEGIN {printf \"%.2f\", ${USED_MEM}/${TOTAL_MEM}*100}")

  USED_ROOT_DIR=$(df -Th | grep '/$' | awk '{print $4}')
  TOTAL_ROOT_DIR=$(df -Th | grep '/$' | awk '{print $3}')
  DISK_USAGE=$(awk "BEGIN {printf \"%.2f\", ${USED_ROOT_DIR}/${TOTAL_ROOT_DIR}*100}")

  last_login(){
    local current_user
    current_user=$(whoami)
    last -n 1 "$current_user" | head -n 1 | awk '{print $4 " " $5 " " $6 " " $7}'
  }

  echo "
  ================ System Information ================
  OS...........: $(head -n 1 /etc/centos-release)
  CPU..........: $(grep -c processor /proc/cpuinfo) core
  Kernel.......: $(uname -r)
  IP...........: $(hostname -I)
  Memory.......: ${USED_MEM} MB / ${TOTAL_MEM} MB (${MEM_USAGE}%)
  DISK(/)......: ${USED_ROOT_DIR} / ${TOTAL_ROOT_DIR} (${DISK_USAGE}%)
  Server Name..: $(hostname)

  ================= User Information =================
  User Name....: $(whoami)
  Last Login...: $(last_login)

  ================= Welcome ! $(whoami) ! =============

  "
EOF
}