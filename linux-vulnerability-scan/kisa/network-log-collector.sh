#!/bin/bash
echo -e "\n##### Date #####\n$(date "+%Y-%m-%d %H:%M:%S")\n" >> "$(date "+%Y%m%d")"_network_session.log
sudo netstat -antpW | grep -e "ESTABLISH" -e "TIME_WAIT" >> "$(date "+%Y%m%d")"_network_session.log