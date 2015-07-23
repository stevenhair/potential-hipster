# potential-hipster

Email address scraper for Python 3. Note that pages are not rendered, so any 
data loaded via javascript will not be searched.

International URI formats are not supported. Only ASCII URIs are 
supported in accordance with [RFC 3986 section 2]
(http://tools.ietf.org/html/rfc3986#section-2). Domains may only contain A-Z, 
0-9, hyphens (-), and periods (.).

SSL certificate verification is disabled, so pages using the `https` protocol can be loaded regardless of whether or not they have a valid SSL certificate.

Note that if a subdomain is entered, the entire parent domain and the parent's 
subdomains will be searched unless the `--exclude-parent` flag is set or the 
`exclude_parent` option is set to True.

## Dependencies

Python 3 is required for this package. It is currently incompatible with Python 2.

All dependencies are listed in requirements.txt and can be installed by running

```sh
pip install -r requirements.txt
```

Alternatively, you can install them manually from PyPI:

 * [Chardet 2.3.0](https://pypi.python.org/pypi/chardet/2.3.0)

## Usage

You can begin searching domains for email addresses by running

```sh
python find_email_addresses.py <domain>
```

Run with `-h` or `--help` for more available options.

### As a Library
```python
>>> import find_email_addresses as find_emails

>>> find_emails.get_emails_in_domain('example.com')
['email1@example.com', 'email2@example.com']
```

