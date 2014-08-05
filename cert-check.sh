#!/bin/bash
#
# @author Gerhard Steinbeis (info [at] tinned-software [dot] net)
# @copyright Copyright (c) 2014
version=0.0.2
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
    echo "      --temp-path         Specify a directory where the script can create files."
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
		FILE_SIG_KEY_ID[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -text |grep -A1 "Authority Key Identifier" |grep -v X509 |sed -e 's/^.*keyid://'`
		FILE_KEY_ID[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -text |grep -A1 "Subject Key Identifier" |grep -v X509 |sed -e 's/^ *//'`
		FILE_SUBJECT[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -subject | sed 's/^subject= //'`
		FILE_ISSUER[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -issuer | sed 's/^issuer= //'`
		FILE_FINGERPRINT[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -fingerprint`
		FILE_SERIAL[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -serial | sed 's/^serial= //'`
		FILE_DATE_START[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -startdate | sed 's/^notBefore= //'`
		FILE_DATE_END[$FLC]=`openssl x509 -in "${FILE}-$TYPE" -noout -enddate | sed 's/^notAfter= //'`
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

	FLC=$((FLC + 1))
done

# Find the child/parent relation between the certificates and match the keys
for (( i = 0; i < $FLC; i++ )); do
	if [[ "${FILE_TYPE[$i]}" == "CERT" ]]; then
		# Check if the certificate is self-signed
		if [[ -z "${FILE_SIG_KEY_ID[$i]}" ]] || [[ "${FILE_SIG_KEY_ID[$i]}" == "${FILE_KEY_ID[$i]}" ]]; then
			FILE_NOTICE[$i]="Self-Signed"
			continue
		fi
		for (( a = 0; a < $FLC; a++ )); do
			# find matching issuer certificate
			if [[ "${FILE_SIG_KEY_ID[$i]}" == "${FILE_KEY_ID[$a]}" ]] && [[ "${FILE_ISSUER_HASH[$i]}" == "${FILE_HASH[$a]}" ]]; then
				FILE_PARENT[$i]=$a;
				FILE_CHILDS[$a]="${FILE_CHILDS[$a]} $i "
			fi
		done
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

# Find the certificate(s) without parent certificate as well as self-signed
for (( i = 0; i < $FLC; i++ )); do
	if [[ "${FILE_PARENT[$i]}" == "" ]] && [[ "${FILE_TYPE[$i]}" == "CERT" ]]; then
		ROOT_LIST="$ROOT_LIST $i"
	fi
done




for (( i = 0; i < $FLC; i++ )); do
	echo "*** DBG:  $i: ${FILE_LIST[$i]}"
	echo "*** DBG:               type: ${FILE_TYPE[$i]} ${FILE_NOTICE[$i]}"
	echo "*** DBG:            subject: ${FILE_SUBJECT[$i]}"
	echo "*** DBG:        fingerprint: ${FILE_FINGERPRINT[$i]}"
	echo "*** DBG:             serial: ${FILE_SERIAL[$i]}"
	echo "*** DBG:          notBefore: ${FILE_DATE_START[$i]}"
	echo "*** DBG:           notAfter: ${FILE_DATE_END[$i]}"
	echo "*** DBG:         public-key: ${FILE_PUB_KEY[$i]}"
	echo "*** DBG:               hash: ${FILE_HASH[$i]}"
	echo "*** DBG:             issuer: ${FILE_ISSUER[$i]}"
	echo "*** DBG:        issuer-hash: ${FILE_ISSUER_HASH[$i]}"
	echo "*** DBG:             key-id: ${FILE_KEY_ID[$i]}"
	echo "*** DBG:   signature-key-id: ${FILE_SIG_KEY_ID[$i]}"
	echo "*** DBG:        parent-cert: ${FILE_PARENT[$i]}"
	echo "*** DBG:        child-certs: ${FILE_CHILDS[$i]}"
done
echo "*** DBG:  ROOT_LIST: $ROOT_LIST"





function print_certificates()
{
	local INTEND="$1"
	shift
	ITEM_LIST=$@

	for k in $ITEM_LIST; do
		echo "${INTEND}Certificate file          : ${FILE_LIST[$k]} (internal-id: $k)"
		echo "${INTEND}Certificate subject       : ${FILE_SUBJECT[$k]} (hash: ${FILE_HASH[$k]})"
		echo "${INTEND}Certificate serial        : ${FILE_SERIAL[$k]} "
		echo "${INTEND}Certificate Key Identifier: ${FILE_KEY_ID[$k]}"
		echo "${INTEND}Issuer Subject            : ${FILE_ISSUER[$k]} (issuer hash: ${FILE_ISSUER_HASH[$k]})"
		echo "${INTEND}Issuer Key Identifier     : ${FILE_SIG_KEY_ID[$k]}"
		echo "${INTEND}*** DBG: parent-cert      : ${FILE_PARENT[$k]} / child-certs: ${FILE_CHILDS[$k]}"
		if [[ "${KEY_ASSIGNMENT[$k]}" -ne "" ]]; then
			KI=${KEY_ASSIGNMENT[$k]}
			echo "${INTEND}***"
			echo "${INTEND}*** Matching Key          : ${FILE_LIST[$KI]}"
			echo "${INTEND}*** DBG: key-parent-cert  : $k"
		fi
		echo ""

		print_certificates "$INTEND    " ${FILE_CHILDS[$k]}

	done

}


print_certificates '' $ROOT_LIST




## print the certificate tree and the key matching
#INTEND=''
#for k in $RESULT_ORDER; do
#	echo "${INTEND}Certificate file: ${FILE_LIST[$k]} (internal-id: $k)"
#	echo "${INTEND}Certificate hash: ${FILE_HASH[$k]} (issuer: ${FILE_ISSUER_HASH[$k]})"
#	SUBJECT=`echo "${FILE_SUBJECT[$k]}" | sed 's/^subject= //'`
#	echo "${INTEND}Certificate subj: $SUBJECT"
#	if [[ "${KEY_ASSIGNMENT[$k]}" -ne "" ]]; then
#		KI=${KEY_ASSIGNMENT[$k]}
#		echo "${INTEND}***"
#		echo "${INTEND}*** Matching Key: ${FILE_LIST[$KI]}"
#	fi
#	echo ""
#
#	INTEND="$INTEND        "
#done
#echo ""





# TEMP COMMANDS
#
# openssl asn1parse -in temp/geotrust_CA-cert.pem_part00-CERTIFICATE
#
#
#
#


#
# LINK LIST
#
# http://www.openssl.org/docs/apps/rsautl.html
# 	- rsauthl seems to be able to show the certificate-signature details
#		http://openssl.6102.n7.nabble.com/verify-signature-using-public-key-td12297.html
#
# http://www.herongyang.com/Cryptography/OpenSSL-Certificate-Path-Validation-Tests.html
# 	- Verify command usage
# 
# http://www.herongyang.com/Cryptography/OpenSSL-Certificate-Path-Create-Sample-Certificates.html
# 	- Create CA and certificate path for testing
# 
# http://www.tinned-software.net//demo/rfc-viewer/rfcview.php?number=5280&loc=remote#page71
# 	- Certificate verification RFC
# 
# http://www.cyberciti.biz/faq/test-ssl-certificates-diagnosis-ssl-certificate/
# 	- get certificate from remote
# 






















