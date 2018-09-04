# DNS Email Security Checker
Author: Dillon Korman

This script checks a list of domains for DNS TXT records that email security systems use. 

## Install

`pip3 install dnspython termcolor`

## Usage

```
usage: dns_checker.py [-h] [-v] [-s] [--spf] [--dmarc] [--nospf] [--nodmarc]
                      [--spf-file SPF_FILE] [--dmarc-file DMARC_FILE]
                      domains_file

positional arguments:
  domains_file          file with list of domains to check

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -s, --stats           prints statistics of results at end
  --spf                 write domains with SPF to an output file
  --dmarc               write domains with DMARC to an output file
  --nospf               write domains without SPF to an output file
  --nodmarc             write domains without DMARC to an output file
  --spf-file SPF_FILE   name of file for SPF output
  --dmarc-file DMARC_FILE
                        name of file for DMARC output

```

## Information
This program requires Python 3.  
This program has a perfect score with pylint.  
This supports SPF and DMARC from TXT records, but it does not check the separate SPF record.  
DKIM is not supported because it requires the knowledge of an unknown selector.

## Potential Improvements
* Add timeout value support
* Download the domain lists 
* Add some DKIM support with common selectors
* Use multithreading 
* Add tests
