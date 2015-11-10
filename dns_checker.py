#!/usr/bin/python
import dns.resolver
import dns.exception
from termcolor import cprint

nospf = list()
nodmarc = list()
num_of_active_domains = 0

print "SPF and DMARC Checker" + "\n" + "By: Dillon Korman" + "\n"

domains = raw_input("Enter the name of domain list: ")

with open(domains) as domain_list:
    for domain in domain_list:
        domain = domain.strip()
        dmarc_nonexistent_domain = set()
        try:
            answers = dns.resolver.query(domain, 'TXT')
            spf_records = set()
            just_txt_records = set()
            no_txt_records = set()
            nonexistent_domain = set()
            for rdata in answers:
                for record in rdata.strings:
                    if record.startswith("v=spf1") is True:
                        spf_records.add(record)
                        cprint(domain + " has an SPF record.", "green")
                        print "Its record is %s" % record
                    else:
                        just_txt_records.add(record)
            if just_txt_records and not spf_records:
                nospf.append(domain)
                cprint(domain + " does not have an SPF record, only other TXT records.", "red")
            num_of_active_domains += 1
        except dns.resolver.NoAnswer:
            cprint(domain + " does not have any TXT records.", "red")
            nospf.append(domain)
            no_txt_records.add(domain)
            num_of_active_domains += 1
        except dns.exception.Timeout:
            cprint(domain + " timed out", "red")
        except dns.resolver.NXDOMAIN:
            cprint(domain + " does not exist", "red")
            nonexistent_domain.add(domain)
            dmarc_nonexistent_domain.add(domain)
        except dns.resolver.NoNameservers:
            cprint(domain + " could not be resolved with the current name servers", "red")
        try:
            if spf_records and not (no_txt_records or nonexistent_domain):
                dmarc_domain = "_dmarc." + domain
                dmarc_answers = dns.resolver.query(dmarc_domain, 'TXT')
                for rdata in dmarc_answers:
                    for record in rdata.strings:
                        if record.startswith("v=DMARC1"):
                            cprint(domain + " does have a DMARC record.", "green")
                            print "Its record is %s" % record
                        else:
                            nodmarc.append(domain)
            elif not dmarc_nonexistent_domain:
                nodmarc.append(domain)
        except dns.resolver.NXDOMAIN:
            cprint(domain + " does not have a DMARC record", "red")
            nodmarc.append(domain)
        except dns.resolver.NoAnswer:
            cprint(domain + " does not have a DMARC record", "red")
        except dns.resolver.NoNameservers:
            cprint("_dmarc." + domain + " could not be resolved with the current name servers", "red")
        except dns.exception.Timeout:
            cprint("_dmarc." + domain + " timed out", "red")

domain_list.close()

nospf_file = open('nospf_domains.txt', 'w')
nodmarc_file = open('nodmarc_domains.txt', 'w')

print "\n" + "Here were the domains with no SPF records:"
for nospf_domain in nospf:
    print nospf_domain
    nospf_file.write("%s\n" % nospf_domain)
nospf_file.close()

print "\n" + "Here were the domains with no DMARC records:"
for nodmarc_domain in nodmarc:
    print nodmarc_domain
    nodmarc_file.write("%s\n" % nodmarc_domain)
nodmarc_file.close()

spf_percentage = str(format(float((len(nospf)) / float(num_of_active_domains) * 100.0), '.2f'))
dmarc_percentage = str(format(float((len(nodmarc)) / float(num_of_active_domains)) * 100.0, '.2f'))
print "\n" + "This means that out of " + str(num_of_active_domains) + " active domains, " + str(len(nospf)) + " of them did not have SPF records." \
    + " That's " + spf_percentage + "%."
print "\n" + "This means that out of " + str(num_of_active_domains) + " active domains, " + str(len(nodmarc)) + " of them did not have DMARC records." \
    + " That's " + dmarc_percentage + "%."