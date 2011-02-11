#!/bin/bash
# Nagios check script for GLSAs (Gentoo Linux Security Advisories)
# Created by Stefan Behte <craig@gentoo.org>
# Inspired by wschlich's version
# Distributed under the terms of the GNU General Public License v2
#
# Needs glsa-check from gentoolkit
#

WHITELISTFILE=/etc/snmp/whitelist

if [ -e "${WHITELISTFILE}" ]
then
	WHITELIST=($(cat ${WHITELISTFILE}))
fi

GLSALIST=($(glsa-check -t affected 2>/dev/null | egrep ^'[0-9]{6}-[0-9]{2}'))
if [[ ${?} -ne 0 ]]
then
	if [ ${#GLSALIST[@]} -eq 0 ]
	then
		echo "OK - system not affected by any GLSAs"
		exit 0
	fi

	echo "ERROR - trouble running glsa-check to get list of GLSAs"
	exit 3
fi

for ((i=0; i<${#GLSALIST[@]}; i++))
do
	if [ $(echo ${WHITELIST[@]} | grep ${GLSALIST[$i]} ) ]
	then
		continue
	fi
	
	NEW_PACKAGES=($(glsa-check -d ${GLSALIST[$i]} | awk -F: '/Affected package: / {print $2}' | tr '\n' ' '))
	if [[ ${?} -ne 0 ]]
	then
		echo "ERROR - trouble running glsa-check to get package name for GLSA ${#GLSALIST[@]}"
		exit 3
	fi

	for ((k=0; k<${#NEW_PACKAGES[@]}; k++))
	do
		GLSA_PACKAGES="${GLSA_PACKAGES} ${NEW_PACKAGES[$k]}"
	done

done

echo "CRITICAL - affecting GLSAs:${GLSA_PACKAGES}"
exit 2

