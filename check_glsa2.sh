#!/bin/bash
# Nagios check script for GLSAs (Gentoo Linux Security Advisories)
# Created by Stefan Behte <craig@gentoo.org>
# Inspired by wschlich's version
# Distributed under the terms of the GNU General Public License v2
#
# Needs glsa-check from gentoolkit
#

WHITELISTFILE=/etc/snmp/whitelist

if [ -f "${WHITELISTFILE}" ]
then
	WHITELIST=($(cat ${WHITELISTFILE}))
fi

GLSALIST=($(glsa-check -t affected 2>/dev/null | egrep ^'[0-9]{6}-[0-9]{2}'))
if [[ ${?} -eq 0 ]]
then

	for ((i=0; i<${#GLSALIST[@]}; i++))
	do
		# if this GLSA-nr is in my whitelist, try next
		if [ "$(echo ${WHITELIST[@]} | grep ${GLSALIST[$i]} )" ]
		then
			continue
		fi

		# get affected packages for this GLSA
		NEW_PACKAGES=($(glsa-check -d ${GLSALIST[$i]} 2>/dev/null | awk -F: '/Affected package: / {print $2}' | tr '\n' ' '))
		if [[ ${?} -ne 0 ]]
		then
			echo "ERROR - trouble running glsa-check to get package name for GLSA ${#GLSALIST[@]}"
			exit 3
		fi

		# only add NEW_PACKAGES[k] to the list of affected packages, if it's not in yet (thanks idl0r)
		for ((k=0; k<${#NEW_PACKAGES[@]}; k++))
		do
			if [[ ! $(echo ${GLSA_PACKAGES[@]} | egrep "\<${NEW_PACKAGES[$k]}\>") ]]
			then
				GLSA_PACKAGES="${GLSA_PACKAGES} ${NEW_PACKAGES[$k]}"
			fi
		done

	done

	# possibly, all vulnerable packages were whitelisted: check if affected packages is empty
	if [ ${#GLSA_PACKAGES[@]} -eq 0 ]
	then
		echo "OK - system not affected by any GLSAs (${#WHITELIST[@]} whitelisted)"
		exit 0
	else
		echo "CRITICAL - affecting GLSAs:${GLSA_PACKAGES}"
		exit 2
	fi

# glsa-check returned no vulnerable packages
elif [[ ${?} -eq 1 ]]
then
	echo "OK - system not affected by any GLSAs (${#WHITELIST[@]} whitelisted)"
	exit 0
fi

echo "ERROR - trouble running glsa-check to get list of GLSAs"
exit 3

