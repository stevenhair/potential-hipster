# potential-hipster

Email address scraper for Python 3. Note that pages are not rendered, so any 
data loaded via javascript will not be searched.

Also note that there is currently a [bug in openssl which may prevent pages 
from being loaded over https](
https://bugs.launchpad.net/ubuntu/+source/openssl/+bug/965371).

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

