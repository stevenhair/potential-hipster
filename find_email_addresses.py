#!/usr/bin/python3
"""Scrape a domain's public web pages for email addresses"""

from argparse import ArgumentParser
from collections import deque
import re
import urllib.request
import urllib.parse
import chardet

class DomainError(ValueError):
    """Error thrown for an invalid domain format."""
    def __init__(self, message=""):
        super(DomainError, self).__init__(message)


def _get_emails_from_string(string):
    """Returns email addresses found in a string.

    Args:
        string: The string to search

    Returns:
        A deque object containing unique email addresses found in s."""

    # We don't need to process through the DOM to find email addresses, we can
    # just search for something formatted like an email address

    emails = deque()
    email_regex = re.compile(r'[\w\.%\+-]+@[\w\.-]+\.[\w]+')

    for email in re.findall(email_regex, string):
        if not emails.count(email):
            emails.append(email)

    return emails

def _is_internal_link(link, domain):
    """Determines whether a given URI is on the provided domain.

    If the privided URI does not have a network location (domain), it is
    assumed to be on the local domain.

    Args:
        link: The URI to check as a string
        domain: The local domain as a string

    Returns:
        True if the link is on domain, false otherwise."""

    netloc_regex = re.compile(r'[\w\.+\-]*' + re.escape(domain) + r'(?:\:\d+)?',
                              re.I)

    url = urllib.parse.urlparse(link)
    if not url.netloc or re.match(netloc_regex, url.netloc):
        return True
    else:
        return False

def _is_binary_link(link):
    """Determines if link is to a know binary file.

    This will speed up processing since we can ignore binary files, which are
    usually fairly sizeable and take a while to download.

    Args:
        link: The link to check

    Returns:
        True if link is to a binary file, false otherwise"""

    extensions = ['pdf', 'jpg', 'png', 'gif', 'zip', 'doc', 'docx']

    url = urllib.parse.urlparse(link)

    for ext in extensions:
        if url.path.lower().endswith(ext.lower()):
            return True

    return False

def _get_links_from_string(string, domain, ignore_binary=True):
    """Returns internal links found in a string.

    Args:
        s: The string to search
        domain: The local domain name as a string

    Returns:
        A deque object containing unique internal links found in s."""

    links = deque()
    # This uses the RFC 3986 URI definition (see
    # http://tools.ietf.org/html/rfc3986#section-2) and matches 'src="<URI>"'
    # and 'href="<URI>"'.
    link_regex = re.compile(r"""(?:(?:src|href)=["'])((?:(?:[a-z]+:)|"""
                            r'(?:\.{1,2}))?\/{1,2}'
                            r"[\w\-\.~:\/\?#\]\[@!\$&'\(\)\*\+,;=%]+)"
                            r"""(?:["'])""", re.I)

    for link in re.findall(link_regex, string):
        if (_is_internal_link(link, domain) and not links.count(link)
                and not (ignore_binary and _is_binary_link(link))):
            links.append(link)

    return links

def _decode_bytestring(string):
    """Decodes and returns a bytestring as a string

    Args:
        s: The bytestring to decode

    Returns:
        A decoded string or an empty string if encoding cannot be determined"""

    enc = chardet.detect(string)

    try:
        if enc['encoding']:
            return string.decode(enc['encoding'])
    # Ignore pages that don't decode. These are usually low confidence anyway.
    except UnicodeDecodeError:
        pass

    return ""

def _assemble_url(link, domain, scheme):
    """Generates a properly formatted URI

    Args:
        link: The raw link to format
        domain: The domain to use if link does not specify
        scheme: The scheme to use if link does not specify

    Returns:
        A properly formatted URL as a string"""

    string = ''
    url = urllib.parse.urlparse(link)

    if url.scheme:
        string += url.scheme + '://'
    else:
        string += scheme + '://'

    if url.netloc:
        string += url.netloc
    else:
        string += domain

    string += url.path

    if url.params:
        string = string + ';' + url.params
    if url.query:
        string = string + '?' + url.query
    if url.fragment:
        string = string + '#' + url.fragment

    return string

def _is_valid_domain(domain):
    """Determines if the provided domain is in a valid format.

    Args:
        domain: The string to test

    Returns:
        True if the domain is valid, false otherwise."""

    # Without the '//',  a domain such as 'example.com' is only a path (see
    # http://en.wikipedia.org/wiki/URI_scheme#Generic_syntax ). Of course, if
    # our domain variable contains any forward slashes, it isn't valid anyway.
    # So, first test to make sure that there are no forward slashes, and then
    # add them in.
    is_valid = True

    if '/' in domain:
        is_valid = False
    else:
        url = urllib.parse.urlparse("//" + domain)
        if url.path or url.params or url.query or url.fragment or not url.netloc:
            is_valid = False

    return is_valid

def get_emails_in_domain(domain, scheme='http', exclude_parent=False,
                         verbosity=0):
    """Returns email addresses found in domain.

    Iterates through publicly accessible pages/files found at
    <scheme>://<domain> and collects all email addresses.

    Args:
        domain: The domain to search as a string
        scheme: The scheme to use (default: http) as a string
        verbosity: The level of verbosity (default: 0, max: 2)

    Returns:
        A list containing unique email addresses found

    Raises:
        DomainError: 'domain' is not a valid domain."""

    if not _is_valid_domain(domain):
        raise DomainError('"{}" is not a valid domain.'.format(domain))

    if exclude_parent:
        domain = domain
    else:
        # If the exclude_parent flag is not set, we need to pull out the parent
        # from the subdomain. Since we'll be searching the whole domain now, we
        # might as well just replace the domain variable. See
        # http://en.wikipedia.org/wiki/Domain_name#Technical_requirements_and_process
        # for the domain name requirements used.
        parent_regex = re.compile(r'(?P<parent>[a-z0-9\-]+\.[a-z0-9\-]+)$',
                                  re.I)
        match = re.search(parent_regex, domain)
        # This should never not match
        if match:
            domain = match.group('parent')
            if verbosity >= 1:
                print('Searching on parent domain "{}"'.format(domain))
        else:
            raise DomainError(
                'Could not separate parent domain from {}. '.format(domain) +
                'Please report this bug to: '
                'https://github.com/stevenhair/potential-hipster/issues')

    emails = deque()
    pages_visited = deque()
    pages_to_visit = deque(['/'])

    while len(pages_to_visit):
        page_contents = ''

        path = pages_to_visit.popleft()
        link = _assemble_url(path, domain, scheme)
        try:
            if verbosity >= 2:
                print('Processing page "{}"...'.format(link))
            with urllib.request.urlopen(link) as page:
                # Make sure that a redirect was not followed
                if _is_internal_link(page.geturl(), domain):
                    page_contents = page.read()
        except urllib.error.HTTPError:
            # Ignore errors from webpages
            if verbosity >= 2:
                print('Could not process page "{}".'.format(link))
        pages_visited.append(path)

        if page_contents:
            page_contents = _decode_bytestring(page_contents)

            for email in _get_emails_from_string(page_contents):
                if not emails.count(email.lower()):
                    emails.append(email.lower())

            for link in _get_links_from_string(page_contents, domain):
                if (not pages_to_visit.count(link)
                        and not pages_visited.count(link)):
                    pages_to_visit.append(link)

    if verbosity >= 1:
        print('Processed {} pages.'.format(len(pages_visited)))

    return list(emails)

def main():
    """Handles user input from the command line."""

    parser = ArgumentParser(
        description='Find email addresses on pages from a given domain.')
    parser.add_argument('--exclude-parent', default=0, action='count',
                        help='do not search parent domain and parent '
                        'subdomains')
    parser.add_argument('--scheme', type=str, default='http',
                        help='scheme to use (default: http)')
    parser.add_argument('-v', '--verbose', default=0, action='count',
                        help='increase verbosity')
    parser.add_argument('domain', type=str, help='domain on which to search')
    args = parser.parse_args()

    print("Finding emails. This could take a while. Please wait...")
    emails = get_emails_in_domain(args.domain, scheme=args.scheme,
                                  exclude_parent=args.exclude_parent,
                                  verbosity=args.verbose)

    if emails:
        for email in emails:
            print(email)
    else:
        print("No emails found at {}.".format(args.domain))

if __name__ == '__main__':
    main()
