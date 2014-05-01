#!/bin/bash
#
# @author Gerhard Steinbeis (info [at] tinned-software [dot] net)
# @copyright Copyright (c) 2014
version=0.0.1
# @license http://opensource.org/licenses/GPL-3.0 GNU General Public License, version 3
# @package monitoring
#


SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

#
# Parse all parameters
#
INPUT_FILE_LIST=''
HELP=0
while [ $# -gt 0 ]; do
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



		# Unnamed parameter        
		*)
			if [[ -f $1 ]]; then
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
if [ "$HELP" -eq "1" ]; then
    echo 
    echo "This script will accept a list of files in PEM format. These files "
    echo "will be analysed to draw the certificate chain as well as it "
    echo "identifies which key is assigned to which certificate."
    echo 
    echo "Usage: `basename $0` [-hv] [--config filename.conf] certificate-file1.pem ... certificate-fileN.pem "
    echo "  -h  --help              Print this usage and exit"
    echo "  -v  --version           Print version information and exit"
    echo "      --cert-path         Specify a directory where the script can create files."
    echo "                          This directory fill later contain the splitted PEM files with the"
    echo "                          different certificates and keys seperated into single files."
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
for FILE in $INPUT_FILE_LIST
do
	# Get the number of parts in this file
	PART_COUNT=`grep "\-\-\-\-\-BEGIN" ${FILE} | wc -l`
	# get the repeat value for the csplit lcommand
	REPEAT_COUNT=$((PART_COUNT - 2))
	

	# get the basename of the certificate file
	FILE_BASENAME=`basename "$FILE"`

	# if only one certificate in the file, copy it over
	if [[ "$REPEAT_COUNT" -lt "0" ]]; then
		echo "*** DBG: $FILE with $PART_COUNT parts ... copy"
		cp "$FILE" "$TEMP_PATH/${FILE_BASENAME}_part00"
		continue
	fi

	# OS specific parameters to execurte csplit
	echo "*** DBG: $FILE with $PART_COUNT parts ... csplit ($DETECTED_OS_TYPE)"
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
for FILE in $TEMP_PATH/*; do
	TYPE=`grep -h "\-\-\-\-\-BEGIN" "$FILE" | sed 's/^.* \([A-Z]*\).*$/\1/'`
	mv "$FILE" "${FILE}-$TYPE"

	# extract and store details for later
	FILE_LIST[$FLC]="${FILE}-$TYPE"
	if [[ "$TYPE" == "CERTIFICATE" ]]; then
		FILE_TYPE[$FLC]='CERT'
		FILE_PUB_KEY[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -modulus | openssl md5`
		FILE_HASH[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -hash`
		FILE_ISSUER_HASH[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -issuer_hash`
		FILE_SUBJECT[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -subject`
	else
		if [[ "$TYPE" == "KEY" ]]; then
			KEY_TYPE=`grep -h "\-\-\-\-\-BEGIN" "${FILE}-$TYPE" | sed 's/^.* \([RD]SA\).*$/\1/' | tr '[:upper:]' '[:lower:]'`
			FILE_TYPE[$FLC]='KEY'
			FILE_PUB_KEY[$FLC]=`openssl $KEY_TYPE -in "${FILE}-$TYPE" -noout -modulus | openssl md5`
			FILE_HASH[$FLC]='-'
			FILE_ISSUER_HASH[$FLC]='-'
			FILE_SUBJECT[$FLC]='-'
		else
			continue
		fi
	fi

	echo "*** DBG:  $FLC: ${FILE_LIST[$FLC]}"
	echo "*** DBG:               type: ${FILE_TYPE[$FLC]}"
	echo "*** DBG:         public-key: ${FILE_PUB_KEY[$FLC]}"
	echo "*** DBG:               hash: ${FILE_HASH[$FLC]}"
	echo "*** DBG:        issuer-hash: ${FILE_ISSUER_HASH[$FLC]}"
	echo "*** DBG:            subject: ${FILE_SUBJECT[$FLC]}"


	FLC=$((FLC + 1))
done

# Find the order of the certificates and match the keys
for (( i = 0; i < $FLC; i++ )); do
	if [[ "${FILE_TYPE[$i]}" == "CERT" ]]; then
		if [[ "$i" -eq "0" ]]; then
			RESULT_ORDER="$i"
		else
			if [[ "${FILE_HASH[$i]}" == "${FILE_ISSUER_HASH[$i - 1]}" ]]; then
				RESULT_ORDER="$i $RESULT_ORDER"
			fi
			if [[ "${FILE_ISSUER_HASH[$i]}" == "${FILE_HASH[$i - 1]}" ]]; then
				RESULT_ORDER="$RESULT_ORDER $i"
			fi
		fi
	fi
	if [[ "${FILE_TYPE[$i]}" == "KEY" ]]; then
		for (( j = 0; j < $FLC; j++ )); do
			if [[ "${FILE_PUB_KEY[$i]}" == "${FILE_PUB_KEY[$j]}" ]] && [[ "${FILE_TYPE[$j]}" == "CERT" ]]; then
				KEY_ASSIGNMENT[$j]=$i;
				echo "*** DBG: Matching key found: Cert: $j match to Key $i."
			fi
		done
	fi
done


printf "*** DBG: CERT chain order: $RESULT_ORDER\n"

echo ""

# print the certificate tree and the key matching
INTEND=''
for k in $RESULT_ORDER; do
	echo "${INTEND}Certificate file: ${FILE_LIST[$k]} (internal-id: $k)"
	echo "${INTEND}Certificate hash: ${FILE_HASH[$k]} (issuer: ${FILE_ISSUER_HASH[$k]})"
	SUBJECT=`echo "${FILE_SUBJECT[$k]}" | sed 's/^subject= //'`
	echo "${INTEND}Certificate subj: $SUBJECT"
	if [[ "${KEY_ASSIGNMENT[$k]}" -ne "" ]]; then
		KI=${KEY_ASSIGNMENT[$k]}
		echo "${INTEND}***"
		echo "${INTEND}*** Matching Key: ${FILE_LIST[$KI]}"
	fi
	echo ""

	INTEND="$INTEND        "
done
echo ""






























