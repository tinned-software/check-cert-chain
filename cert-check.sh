#!/bin/bash
#
# @author Gerhard Steinbeis (info [at] tinned-software [dot] net)
# @copyright Copyright (c) 2014
version=0.1.0
# @license http://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3
# @package monitoring
#


SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

#
# Parse all parameters
#
INPUT_FILE_LIST=''
HELP=0
while [ $# -gt 0 ]
do
	case $1 in
		# General parameter
		-h|--help)
			HELP=1
			shift
			;;
		-v|--version)
			echo 
			echo "Copyright (c) 2014 Tinned-Software (Gerhard Steinbeis)"
			echo "License GNUv3: GNU General Public License version 3 <http://opensource.org/licenses/GPL-3.0>"
			echo 
			echo "`basename $0` version $version"
			echo
			exit 0
			;;

		# specific parameters
		--temp-path)
			TEMP_PATH=$2
			shift 2
			;;

		--chain-for-key)
			CHAIN_FOR_KEY="YES"
			shift 1
			;;

		--save-chain)
			SAVE_CHAIN="YES"
			shift 1
			;;

		# Unnamed parameter        
		*)
			if [[ -f $1 ]]
			then
				INPUT_FILE_LIST="$INPUT_FILE_LIST $1"
			else
				echo "Unknown option '$1'"
				HELP=1
			fi
			shift
			;;
	esac
done


# Check required parameters
if [ "$INPUT_FILE_LIST" == "" ]
then
	echo "At least one file parameter is required."
	HELP=1
fi
if [ "$TEMP_PATH" == "" ]
then
	echo "The parameter --cert-path is missing."
	HELP=1
fi



# show help message
if [ "$HELP" -eq "1" ]
then
	echo 
	echo "This script will accept a list of files in PEM format. These files "
	echo "will be analysed to draw the certificate chain as well as it "
	echo "identifies which key is assigned to which certificate."
	echo 
	echo "Usage: `basename $0` [-hv] [--temp-path /path/to/temp/director/] [--chain-for-key cert-key.key] [--save-chain] cert-file1.pem ... cert-fileN.pem "
	echo "  -h  --help              Print this usage and exit"
	echo "  -v  --version           Print version information and exit"
	echo "      --temp-path         Specify a directory where the script can create files"
	echo "                          This directory fill later contain the splitted PEM files with the"
	echo "                          different certificates and keys seperated into single files"
	echo "      --chain-for-key     Create the chain for the key (key needs to be provided in the files)"
	echo "      --save-chain        Save the chain files as key, certificate and chain"
	echo 
	exit 1
fi


# change the command used according to the OS specifics
# Mac OS X ... Darwin
# Linux ...... Linux
DETECTED_OS_TYPE=`uname -s`


#
# http://www.openssl.org/docs/apps/openssl.html
#
rm -f $TEMP_PATH/*

# for each file do
echo 
echo -n "*** Splitting up files into certificates and keys ..."
for FILE in $INPUT_FILE_LIST
do
	# Get the number of parts in this file
	PART_COUNT=`grep "\-\-\-\-\-BEGIN" ${FILE} | wc -l`
	# get the repeat value for the csplit lcommand
	REPEAT_COUNT=$((PART_COUNT - 2))
	

	# get the basename of the certificate file
	FILE_BASENAME=`basename "$FILE"`

	# if only one certificate in the file, copy it over
	if [[ "$REPEAT_COUNT" -lt "0" ]]
	then
		#echo "*** DBG: $FILE with $PART_COUNT parts ... copy"
		cp "$FILE" "$TEMP_PATH/${FILE_BASENAME}_part00"
		continue
	fi

	# OS specific parameters to execurte csplit
	#echo "*** DBG: $FILE with $PART_COUNT parts ... csplit ($DETECTED_OS_TYPE)"
	case $DETECTED_OS_TYPE in 
		Linux)
			csplit --elide-empty-files -s -f $TEMP_PATH/${FILE_BASENAME}_part $FILE '/-----BEGIN/' '{*}'
			;;
		Darwin)
			csplit -s -f $TEMP_PATH/${FILE_BASENAME}_part $FILE '/-----BEGIN/' "{$REPEAT_COUNT}"
			;;
	esac
done


FLC=0
KEY_LIST=''
for FILE in $TEMP_PATH/*
do
	TYPE=`grep -h "\-\-\-\-\-BEGIN" "$FILE" | sed 's/^.* \([A-Z]*\).*$/\1/'`
	mv "$FILE" "${FILE}-$TYPE"

	# extract and store details for later
	FILE_LIST[$FLC]="${FILE}-$TYPE"
	if [[ "$TYPE" == "CERTIFICATE" ]]
	then
		FILE_TYPE[$FLC]='CERT'
		FILE_PUB_KEY[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -modulus | openssl md5`
		FILE_HASH[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -hash`
		FILE_ISSUER_HASH[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -issuer_hash`
		FILE_SIG_KEY_ID[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -text |grep -A1 "Authority Key Identifier" |grep -v X509 |sed -e 's/^.*keyid://'`
		FILE_KEY_ID[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -text |grep -A1 "Subject Key Identifier" |grep -v X509 |sed -e 's/^ *//'`
		FILE_SUBJECT[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -subject | sed 's/^subject= //'`
		FILE_ISSUER[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -issuer | sed 's/^issuer= //'`
		FILE_FINGERPRINT[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -fingerprint`
		FILE_SERIAL[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -serial | sed 's/^serial= //'`
		FILE_DATE_START[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -startdate | sed 's/^notBefore= //'`
		FILE_DATE_END[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -enddate | sed 's/^notAfter= //'`
	else
		if [[ "$TYPE" == "KEY" ]]
		then
			KEY_TYPE=`grep -h "\-\-\-\-\-BEGIN" "${FILE}-$TYPE" | sed 's/^.* \([RD]SA\).*$/\1/' | tr '[:upper:]' '[:lower:]'`
			FILE_TYPE[$FLC]='KEY'
			FILE_PUB_KEY[$FLC]=`openssl $KEY_TYPE -in "${FILE}-$TYPE" -noout -modulus | openssl md5`
			FILE_HASH[$FLC]='-'
			FILE_ISSUER_HASH[$FLC]='-'
			FILE_SUBJECT[$FLC]='-'
			KEY_LIST="$KEY_LIST$FLC "
		else
			continue
		fi
	fi

	FLC=$((FLC + 1))
done
echo " $FLC items found"

# Find the child/parent relation between the certificates and match the keys
for (( i = 0; i < $FLC; i++ ))
do
	if [[ "${FILE_TYPE[$i]}" == "CERT" ]]
	then
		# Check if the certificate is self-signed
		if [[ -z "${FILE_SIG_KEY_ID[$i]}" ]] || [[ "${FILE_SIG_KEY_ID[$i]}" == "${FILE_KEY_ID[$i]}" ]]
		then
			FILE_NOTICE[$i]="Self-Signed"
			continue
		fi
		for (( a = 0; a < $FLC; a++ ))
		do
			# find matching issuer certificate
			if [[ "${FILE_SIG_KEY_ID[$i]}" == "${FILE_KEY_ID[$a]}" ]] && [[ "${FILE_ISSUER_HASH[$i]}" == "${FILE_HASH[$a]}" ]]
			then
				FILE_PARENT[$i]=$a;
				FILE_CHILDS[$a]="${FILE_CHILDS[$a]}$i "
			fi
		done
	fi
	if [[ "${FILE_TYPE[$i]}" == "KEY" ]]
	then
		for (( j = 0; j < $FLC; j++ ))
		do
			if [[ "${FILE_PUB_KEY[$i]}" == "${FILE_PUB_KEY[$j]}" ]] && [[ "${FILE_TYPE[$j]}" == "CERT" ]]; then
				KEY_ASSIGNMENT[$j]=$i;
				FILE_PARENT[$i]=$j;
				FILE_CHILDS[$j]="${FILE_CHILDS[$j]}$i "
			fi
		done
	fi
done

# Find the certificate(s) without parent certificate as well as self-signed
for (( i = 0; i < $FLC; i++ ))
do
	if [[ "${FILE_PARENT[$i]}" == "" ]] && [[ "${FILE_TYPE[$i]}" == "CERT" ]]; then
		ROOT_LIST="$ROOT_LIST $i"
	fi
done


#for (( i = 0; i < $FLC; i++ ))
#do
#	echo "*** DBG:  $i: ${FILE_LIST[$i]}"
#	echo "*** DBG:               type: ${FILE_TYPE[$i]} ${FILE_NOTICE[$i]}"
#	echo "*** DBG:            subject: ${FILE_SUBJECT[$i]}"
#	echo "*** DBG:        fingerprint: ${FILE_FINGERPRINT[$i]}"
#	echo "*** DBG:             serial: ${FILE_SERIAL[$i]}"
#	echo "*** DBG:          notBefore: ${FILE_DATE_START[$i]}"
#	echo "*** DBG:           notAfter: ${FILE_DATE_END[$i]}"
#	echo "*** DBG:         public-key: ${FILE_PUB_KEY[$i]}"
#	echo "*** DBG:               hash: ${FILE_HASH[$i]}"
#	echo "*** DBG:             issuer: ${FILE_ISSUER[$i]}"
#	echo "*** DBG:        issuer-hash: ${FILE_ISSUER_HASH[$i]}"
#	echo "*** DBG:             key-id: ${FILE_KEY_ID[$i]}"
#	echo "*** DBG:   signature-key-id: ${FILE_SIG_KEY_ID[$i]}"
#	echo "*** DBG:        parent-cert: ${FILE_PARENT[$i]}"
#	echo "*** DBG:        child-certs: ${FILE_CHILDS[$i]}"
#done
#echo "*** DBG:  ROOT_LIST: $ROOT_LIST"



#
# Function to print the complete certificate chain
#
function print_certificate_details()
{
	local INTEND="$1"
	local k=$2

	if [[ "${FILE_TYPE[$k]}" == "CERT" ]]
	then
		echo "${INTEND}Certificate file          : ${FILE_LIST[$k]} (internal-id: $k)"
		echo "${INTEND}Certificate subject       : ${FILE_SUBJECT[$k]} (hash: ${FILE_HASH[$k]})"
		echo "${INTEND}Certificate serial        : ${FILE_SERIAL[$k]} "
		echo "${INTEND}Certificate Key Identifier: ${FILE_KEY_ID[$k]}"
		echo "${INTEND}Certificate Key hash      : ${FILE_PUB_KEY[$k]}"
		echo "${INTEND}Issuer Subject            : ${FILE_ISSUER[$k]} (issuer hash: ${FILE_ISSUER_HASH[$k]})"
		echo "${INTEND}Issuer Key Identifier     : ${FILE_SIG_KEY_ID[$k]}"
		echo "${INTEND}Parent item in chain      : ${FILE_PARENT[$k]}"
		echo "${INTEND}Child item in chain       : ${FILE_CHILDS[$k]}"
	fi

	if [[ "${FILE_TYPE[$k]}" == "KEY" ]]
	then
		echo "${INTEND}Key file                  : ${FILE_LIST[$k]} (internal-id: $k)"
		echo "${INTEND}Key hash                  : ${FILE_PUB_KEY[$k]}"
		echo "${INTEND}Parent item in chain      : ${FILE_PARENT[$k]}"
	fi

	echo ""
}


#
# Function to print the complete certificate chain
#
function print_certificates()
{
	local INTEND="$1"
	shift
	local ITEM_LIST=$@

	for k in $ITEM_LIST; do
		print_certificate_details "$INTEND" "$k"
		print_certificates "$INTEND    " ${FILE_CHILDS[$k]}
	done

}

#
# Print the chain for one item by checking the parent relation (also saving the chain)
#
function print_chain_for_item()
{
	local INTEND="$1"
	local ITEM="$2"

	# find the first parent 
	ITEM_PARENT="${FILE_PARENT[$ITEM]}"

	# start the certificate path for saving the certificate chain into a file
	if [[ "${FILE_TYPE[$ITEM]}" == "CERT" ]]
	then
		# if the start item is a certificate, then there is no key available for it
		ITEM_PATH_SAVE="$ITEM_PARENT"
		ITEM_PATH_SAVE_KEY=""
		ITEM_PATH_SAVE_CERT="$ITEM"
	else
		# if the start item is a key define the key and the first parent as the certificate
		ITEM_PATH_SAVE=""
		ITEM_PATH_SAVE_KEY="$ITEM"
		ITEM_PATH_SAVE_CERT="$ITEM_PARENT"
	fi
	
	# start the chain to display including the key and the certificate
	ITEM_PATH="$ITEM_PARENT $ITEM"

	# get through the parent relationship to find the root element
	while [[ $ITEM_PARENT != '' ]]
	do
		ITEM_PARENT=${FILE_PARENT[$ITEM_PARENT]}
		ITEM_PATH="$ITEM_PARENT $ITEM_PATH"
		# ignore the root element for the certificate chain
		if [[ $ITEM_PARENT != '' ]]
		then
			# if there is a parent item, add the item to the chain
			ITEM_PATH_SAVE="$ITEM_PATH_SAVE $ITEM_PARENT"
		fi
		
	done

	# show the certificate chain
	for i in $ITEM_PATH
	do
		print_certificate_details "$INTEND" "$i"
		INTEND="$INTEND    "
	done

	# save the certificate chain in reverse order and without the root certificate
	if [[ "$SAVE_CHAIN" = "YES" ]]
	then
		for j in $ITEM_PATH_SAVE
		do
			cat "${FILE_LIST[$j]}" >>"$TEMP_PATH/result-$2-chain.pem"
			cat "${FILE_LIST[$ITEM_PATH_SAVE_CERT]}" >>"$TEMP_PATH/result-$2-cert.pem"
			cat "${FILE_LIST[$ITEM_PATH_SAVE_KEY]}" >>"$TEMP_PATH/result-$2-key.pem"
		done
	fi
}


# 
# Show the result according to the requested parameters
# 
if [[ -z "$CHAIN_FOR_KEY" ]]
then
	print_certificates '' $ROOT_LIST
else
	for i in $KEY_LIST
	do
		echo "========================="
		print_chain_for_item '' "$i"
		echo "========================="
		echo 
	done
fi

exit 0
