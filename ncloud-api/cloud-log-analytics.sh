#!/bin/bash
#### Base Request Command ####
# curl -X GET "URL"
# -H "accept: application/json"
# -H "x-ncp-iam-access-key: $ACCESSKEY"
# -H "x-ncp-apigw-timestamp: $TIMESTAMP"
# -H "x-ncp-apigw-signature-v2: $SIGNATURE"

#### Base Region : FKR
#### Base Zone : FKR-1 / FKR-2

makeSignature(){
  nl=$'\\n'

  TIMESTAMP="$(($(date +%s%N)/1000000))"
  ACCESSKEY=""
  local SECRETKEY=""

  local METHOD=$1
  local URI=$2

  SIG="$METHOD"' '"$URI"${nl}
  SIG+="$TIMESTAMP"${nl}
  SIG+="$ACCESSKEY"

  SIGNATURE=$(echo -n -e "$SIG" | iconv -t utf8 | openssl dgst -sha256 -hmac "$SECRETKEY" -binary | openssl enc -base64)
}

#URI="/vserver/v2/getZoneList"
#makeSignature "GET" $URI
getServerInstanceID(){
  local URI="/vserver/v2/getServerInstanceList"
  local query
  query="regionCode=FKR&serverName=$(hostname)&ip=$(ip -br a s | tail -n 1 | awk '{print $3}' | cut -d'/' -f1)&responseFormatType=json"
  makeSignature "GET" "${URI}?${query}"

  curl -s -X GET "https://fin-ncloud.apigw.fin-ntruss.com${URI}?${query}" \
  -H "accept: application/json" \
  -H "x-ncp-iam-access-key: $ACCESSKEY" \
  -H "x-ncp-apigw-timestamp: $TIMESTAMP" \
  -H "x-ncp-apigw-signature-v2: $SIGNATURE"
}

# getServerInstanceID
INSTANCE_NUMBER=$(getServerInstanceID | jq -r '.getServerInstanceListResponse.serverInstanceList[0].serverInstanceNo')

setCollectServerLog(){
  local URI="/api/v1/vpc/servers/collecting-infos"
  local HOST=$(hostname)
  local IP=$(ip -br a s | tail -n 1 | awk '{print $3}' | cut -d'/' -f1)
  #local query
  #query="logPath=/var/log/secure*&logTemplate=Security&logType=security_log&servername=$(hostname)&osType=Ubuntu+20&ip=$(ip -br a s | tail -n 1 | awk '{print $3}' | cut -d'/' -f1)&instanceNO=${INSTANCE_NUMBER}"
  makeSignature "POST" "${URI}"

  curl -s -X POST "https://cloudloganalytics.apigw.fin-ntruss.com${URI}" \
  -H "Content-Type: application/json" \
  -H "x-ncp-iam-access-key: $ACCESSKEY" \
  -H "x-ncp-apigw-timestamp: $TIMESTAMP" \
  -H "x-ncp-apigw-signature-v2: $SIGNATURE" \
  -d @- <<EOF
  {
    "collectingInfos": [
      {
        "logPath": "/var/log/auth.log*",
        "logTemplate": "Security",
        "logType": "security_log",
        "servername": "$HOST",
        "osType": "Ubuntu 20",
        "ip": "$IP",
        "instanceNo": $INSTANCE_NUMBER
      }
    ]
  }
EOF
}