# check-cert-chain
This script reads the provided PEM certifiacte and key files and splits them into the seperate certificates and keys. By matching the keys to the certificate and the signatur of the certificate to there signing certificate, it prints the chain of certificates down to the key. 

It is also supported to export the required files based on a key specified. While exporting, the key is writen into a key file, the certificate matching the key into a certificate file  and the required CA certificate into a chain file.

    This script will accept a list of files in PEM format. These files 
    will be analysed to draw the certificate chain as well as it 
    identifies which key is assigned to which certificate.

    Usage: check-cert-chain.sh [-hv] [--temp-path /path/to/temp/director/] [--chain-for-key cert-key.key] [--save-chain] cert-file1.pem ... cert-fileN.pem 
      -h  --help              Print this usage and exit
      -v  --version           Print version information and exit
          --temp-path         Specify a directory where the script can create files
                              This directory fill later contain the splitted PEM files with the
                              different certificates and keys seperated into single files
          --chain-for-key     Create the chain for the key (key needs to be provided in the files)
          --save-chain        Save the chain files as key, certificate and chain
      -d                      Show more details about the certificate chain


