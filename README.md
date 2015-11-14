# DNS Email Security Checker
Author: Dillon Korman

This script checks a list of domains for DNS TXT records that email security systems use. 

## Install
`pip install dnspython termcolor`

## Usage

`python dns_checker.py`

## Information
The script prompts you for the file of domains to open.  
This supports SPF and DMARC from TXT records, but it does not check the separate SPF record.  
DKIM is not supported because it requires the knowledge of an unknown selector.

## Potential Improvements
* Add argument parser for increased flexibility (text output, file output, domain list, timeout value)
* Download the domain lists 
* Add some DKIM support with common selectors
* Shorten or optimize code
* Use multithreading
* Update to Python 3
