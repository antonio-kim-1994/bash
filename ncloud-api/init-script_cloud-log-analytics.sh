#!/bin/bash
# Common Variable
SCRIPT_DIR="" # ex) /root/cloud-log-analytics.sh
. "${SCRIPT_DIR}"

collectKey=$(setCollectServerLog | jq -r '.result')

echo -E "
=======================================================
============ Cloud Log Analytics Agent 설치 ===========
=======================================================
"

curl -s http://ccm.fin-ncloud.com/setUpCla/"${collectKey}" | sudo sh