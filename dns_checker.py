#!/usr/bin/env python3
"""This module will check the DNS records of domains to see if they have
records that are primarily used to enforce email security.

The program takes in a file with a domain list.

The user can specify whether or not they wish to print the results of each
domain (verbose), print the final statistics, or write the domains with or
without a specific technology to output files.

The program looks at SPF and DMARC. A domain can't support DMARC without
first supporting SPF.
"""
import argparse
import contextlib
import sys

import dns.exception
import dns.resolver
from termcolor import cprint

TXT_RECORD = 'TXT'
SPF_STARTING_VALUE = b'v=spf1'
DMARC_DOMAIN_PREFIX = '_dmarc.'
DMARC_STARTING_VALUE = b'v=DMARC1'
SPF_OUTPUT_FILE = 'spf_domains.txt'
DMARC_PUTPUT_FILE = 'dmarc_domains.txt'
NO_SPF_OUTPUT_FILE = 'no_spf_domains.txt'
NO_DMARC_OUTPUT_FILE = 'no_dmarc_domains.txt'


def handle_dns_exception(dns_exception, exception_context,
                         domain, active_domains=None, dmarc_domain=None):
    """[Handle exceptions for DNS queries]

    Args:
        dns_exception ([dns.exception.DNSException]): [The DNS exception]
        exception_context ([str]): [The context of the exception, i.e. spf or dmarc]
        domain ([str]): [The current domain]
        active_domains ([set], optional): Defaults to None. [Set of active domains]
        dmarc_domain ([str], optional): Defaults to None. [Name of DMARC domain]
    """
    if isinstance(dns_exception, dns.resolver.NoAnswer):
        if exception_context == 'spf':
            active_domains.add(domain)
            cprint('{} does not have any TXT records'.format(domain), 'red')
        elif exception_context == 'dmarc':
            cprint('{} does not have a DMARC record'.format(domain), 'red')

    elif isinstance(dns_exception, dns.exception.Timeout):
        if exception_context == 'spf':
            cprint('{} timed out'.format(domain), 'red')
        elif exception_context == 'dmarc':
            cprint('{} timed out'.format(dmarc_domain), 'red')

    elif isinstance(dns_exception, dns.resolver.NXDOMAIN):
        if exception_context == 'spf':
            cprint('{} does not exist'.format(domain), 'red')
        elif exception_context == 'dmarc':
            cprint('{} does not have a DMARC record'.format(domain), 'red')

    elif isinstance(dns_exception, dns.resolver.NoNameservers):
        if exception_context == 'spf':
            cprint('{} could not be resolved with the current name servers'.format(
                domain), 'red')
        elif exception_context == 'dmarc':
            cprint('{} could not be resolved with the current name servers'.format(
                dmarc_domain), 'red')


def print_statistics(num_of_active_domains,
                     num_of_spf_domains, num_of_dmarc_domains):
    """[Print statistics of the results]

    Args:
        num_of_active_domains ([int]): [Number of active domains]
        num_of_spf_domains ([int]): [Number of SPF domains]
        num_of_dmarc_domains ([int]): [Number of DMARC domains]
    """

    print('Out of {} active domains, {}, or {:.2f}%, had SPF enabled'.format(
        num_of_active_domains, num_of_spf_domains,
        num_of_spf_domains/num_of_active_domains * 100))
    print('Out of {} active domains, {}, or {:.2f}%, had DMARC enabled'.format(
        num_of_active_domains, num_of_dmarc_domains,
        num_of_dmarc_domains/num_of_active_domains * 100))


def write_domains(active_domains, spf_domains, dmarc_domains, parser_args):
    """[Write the domain results to disk]

    Args:
        active_domains ([set]): [Set of active domains]
        spf_domains ([set]): [Set of SPF domains]
        dmarc_domains ([set]): [Set of DMARC domains]
        parser_args ([argparse.Namespace]): [Command line arguments from ArgumentParser]
    """
    desire_spf_output = parser_args.spf or parser_args.nospf
    desire_dmarc_output = parser_args.dmarc or parser_args.nodmarc

    if desire_spf_output:
        spf_output_file = open(parser_args.spf_file, 'w')
    if desire_dmarc_output:
        dmarc_output_file = open(parser_args.dmarc_file, 'w')

    if parser_args.spf:
        for domain in spf_domains:
            spf_output_file.write('{}\n'.format(domain))
    elif parser_args.nospf:
        no_spf_domains = active_domains.difference(spf_domains)
        for domain in no_spf_domains:
            spf_output_file.write('{}\n'.format(domain))

    if parser_args.dmarc:
        for domain in dmarc_domains:
            dmarc_output_file.write('{}\n'.format(domain))
    elif parser_args.nodmarc:
        no_dmarc_domains = active_domains.difference(dmarc_domains)
        for domain in no_dmarc_domains:
            dmarc_output_file.write('{}\n'.format(domain))

    if desire_spf_output:
        spf_output_file.close()
    if desire_dmarc_output:
        dmarc_output_file.close()


def check_domains(domain_file, verbose):
    """[Perform DNS queries to check for SPF and DMARC records]

    Args:
        domain_file ([str]): [Path to domain file]
        verbose ([boolean]): [Flag for verbose output]

    Returns:
        [tuple]: [A tuple of the active, SPF, and DMARC domain sets]
    """

    active_domains = set()
    spf_domains = set()
    dmarc_domains = set()

    # redirect stdout to nothing if verbose is not enabled, otherwise keep it the same
    with contextlib.redirect_stdout(sys.stdout if verbose else None):
        with open(domain_file) as domain_list:
            for domain in domain_list:
                domain = domain.strip()

                try:
                    dns_response = dns.resolver.query(domain, TXT_RECORD)
                    active_domains.add(domain)
                    found_spf = False
                    for txt_records in dns_response:
                        txt_record_value = txt_records.strings[0]
                        if txt_record_value.startswith(
                                SPF_STARTING_VALUE) is True:
                            spf_domains.add(domain)
                            found_spf = True
                            cprint('{} has an SPF record'.format(
                                domain), 'green')
                            cprint('Its record is {}'.format(
                                txt_record_value.decode('utf8')), 'white')
                            break
                    if not found_spf:
                        cprint('{} does not have an SPF record, only other TXT records'.format(
                            domain), 'red')
                        continue

                except dns.exception.DNSException as dns_exception:
                    handle_dns_exception(
                        dns_exception, 'spf', domain, active_domains)
                    continue

                try:
                    dmarc_domain = DMARC_DOMAIN_PREFIX + domain
                    dns_response = dns.resolver.query(dmarc_domain, TXT_RECORD)
                    found_dmarc = False
                    for txt_records in dns_response:
                        txt_record_value = txt_records.strings[0]
                        if txt_record_value.startswith(
                                DMARC_STARTING_VALUE) is True:
                            dmarc_domains.add(domain)
                            found_dmarc = True
                            cprint('{} does have a DMARC record'.format(
                                domain), 'green')
                            cprint('Its record is {}'.format(
                                txt_record_value.decode('utf8')), 'white')
                            break
                    if not found_dmarc:
                        cprint('{} does not have a DMARC record, only a SPF record'.format(
                            domain), 'red')

                except dns.exception.DNSException as dns_exception:
                    handle_dns_exception(
                        dns_exception, 'dmarc', domain, dmarc_domain=dmarc_domain)
                    continue

    return active_domains, spf_domains, dmarc_domains


def parse_args():
    """[Parse the command line arguments]

    Returns:
        [argparse.Namespace]: [Command line arguments]
    """

    parser = argparse.ArgumentParser()
    parser.add_argument(
        'domains_file', help='file with list of domains to check')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='increase output verbosity')
    parser.add_argument('-s', '--stats', action='store_true',
                        help='prints statistics of results at end')
    parser.add_argument('--spf', action='store_true', default=False,
                        help='write domains with SPF to an output file',)
    parser.add_argument('--dmarc', action='store_true', default=False,
                        help='write domains with DMARC to an output file')
    parser.add_argument('--nospf', action='store_true', default=False,
                        help='write domains without SPF to an output file')
    parser.add_argument('--nodmarc', action='store_true', default=False,
                        help='write domains without DMARC to an output file')
    parser.add_argument(
        '--spf-file', help='name of file for SPF output', default=SPF_OUTPUT_FILE)
    parser.add_argument(
        '--dmarc-file', help='name of file for DMARC output', default=DMARC_PUTPUT_FILE)

    parser_args = parser.parse_args()
    if parser_args.nospf and parser_args.spf_file == SPF_OUTPUT_FILE:
        parser_args.spf_file = NO_SPF_OUTPUT_FILE
    if parser_args.nodmarc and parser_args.dmarc_file == DMARC_PUTPUT_FILE:
        parser_args.dmarc_file = NO_DMARC_OUTPUT_FILE

    return parser_args


def main(parser_args):
    """[Run the program]

    Args:
        parser_args ([argparse.Namespace]): [Command line arguments]
    """

    active_domains, spf_domains, dmarc_domains = check_domains(
        parser_args.domains_file, parser_args.verbose)
    if parser_args.stats:
        print_statistics(len(active_domains), len(
            spf_domains), len(dmarc_domains))

    write_desired = parser_args.spf or parser_args.nospf or parser_args.dmarc or parser_args.nodmarc
    if write_desired:
        write_domains(active_domains, spf_domains, dmarc_domains, parser_args)


if __name__ == '__main__':
    PARSER_ARGS = parse_args()
    main(PARSER_ARGS)
