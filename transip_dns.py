#!/usr/bin/env python

import rsa
import suds
import time
import uuid
import base64
import urllib
import logging
import ipaddress

from collections import OrderedDict
from ansible.module_utils.basic import *
from ansible.module_utils.facts import *
from suds.xsd.doctor import ImportDoctor, Import
from suds.sudsobject import Object as SudsObject

DOCUMENTATION = '''

With this api you can add, update and delete transip dns entries

Original code for python TransIP api can be found here: https://github.com/mhogerheijde/transip-api

- Make sure you have an account at TransIP
- Enable the API (https://www.transip.nl/cp/mijn-account/#api)
- Add your IP.

- Generate key-pairs
    Copy-paste the key into a file (transip.key)
    Generate the rsa key (for now, only unencrypted RSA is supported)
        $ openssl rsa -in transip.key -out transip_rsa.key
    convert the transip_rsa.key to a single line key with newline characters
        $ while read line; do printf "%s" "$line\n"; done < transip_rsa.key
    paste the output quoted into the token value field

'''

EXAMPLES = '''

---
- name: Update dns
  become: no
  local_action: transip_dns
    state=present
    entry=update
    login=john_do
    token='-----BEGIN RSA PRIVATE KEY-----\n PRIVATE KEY DATA \n-----END RSA PRIVATE KEY-----\n'
    domain=example.com
    host=www
    expire=300
    type=CNAME
    content=@
    old_content=  # to remove or update non CNAME records
  tags:
    - transip
    - transip_dns_entry

'''

URI_TEMPLATE = "https://api.transip.nl/wsdl/?service={}"

MODE_RO = 'readonly'
MODE_RW = 'readwrite'
__version__ = '0.1.0-Ansible'


class Client(object):
    """
    A client-base class, for other classes to base their service implementation
    on. Contains methods to set and sign cookie and to retrieve the correct
    WSDL for specific parts of the TransIP API.
    """

    endpoint = 'api.transip.nl'
    service_name = None
    soap_client = None
    url = None

    def __init__(self, service_name):
        """ Initialiser. """
        self.login = module.params.get('login')
        self.private_key = module.params.get('token')
        self.service_name = service_name
        self.url = URI_TEMPLATE.format(self.service_name)
        self._init_soap_client()

    def _sign(self, message):
        """ Uses the decrypted private key to sign the message. """
        signature = None
        keydata = self.private_key.replace('\\n', '\n')
        privkey = rsa.PrivateKey.load_pkcs1(keydata)
        signature = rsa.sign(message, privkey, 'SHA-512')
        signature = base64.b64encode(signature)
        signature = urllib.quote_plus(signature)

        return signature

    def _build_signature_message(self, service_name, method_name,
                                 timestamp, nonce, additional=None):
        """
        Builds the message that should be signed. This message contains
        specific information about the request in a specific order.
        """
        if additional is None:
            additional = []

        sign = OrderedDict()
        # Add all additional parameters first
        for index, value in enumerate(additional):
            if isinstance(value, list):
                for entryindex, entryvalue in enumerate(value):
                    if isinstance(entryvalue, SudsObject):
                        for objectkey, objectvalue in entryvalue:
                            sign[str(index) + '[' + str(entryindex) + '][' + objectkey + ']'] = objectvalue
            else:
                sign[index] = value
        sign['__method'] = method_name
        sign['__service'] = service_name
        sign['__hostname'] = self.endpoint
        sign['__timestamp'] = timestamp
        sign['__nonce'] = nonce

        return urllib.urlencode(sign).replace('%5B', '[').replace('%5D', ']').replace('+', '%20')

    def update_cookie(self, cookies):
        """ Updates the cookie for the upcoming call to the API. """
        temp = []
        for k, val in cookies.items():
            temp.append("%s=%s" % (k, val))

        cookiestring = ';'.join(temp)
        self.soap_client.set_options(headers={'Cookie': cookiestring})

    def build_cookie(self, method, mode, parameters=None):
        """
        Build a cookie for the request.

        Keword arguments:
        method -- the method to be called on the service.
        mode -- Read-only (MODE_RO) or read-write (MODE_RW)
        """
        timestamp = int(time.time())
        nonce = str(uuid.uuid4())[:32]

        signature = self._sign(self._build_signature_message(
            service_name=self.service_name, method_name=method,
            timestamp=timestamp, nonce=nonce, additional=parameters))

        cookies = {
            "nonce": nonce,
            "timestamp": timestamp,
            "mode": mode,
            "clientVersion": __version__,
            "login": self.login,
            "signature": signature,
        }

        return cookies

    def _init_soap_client(self):
        """ Initialises the suds soap-client """
        imp = Import('http://schemas.xmlsoap.org/soap/encoding/')
        doc = ImportDoctor(imp)
        self.soap_client = suds.client.Client(self.url, doctor=doc)


class DomainService(Client):
    """ Representation of the DomainService API calls for TransIP """

    def __init__(self):
        Client.__init__(self, 'DomainService')

    def get_domain_names(self):
        """
            Retrieves a list of all domains currently available
            for this account.
        """
        cookie = self.build_cookie(mode=MODE_RO, method='getDomainNames')
        self.update_cookie(cookie)

        return self.soap_client.service.getDomainNames()

    def get_info(self, domain_name):
        """Retrieves information about the requested domain-name."""

        cookie = self.build_cookie(mode=MODE_RO, method='getInfo', parameters=[domain_name])
        self.update_cookie(cookie)

        return self.soap_client.service.getInfo(domain_name)

    def set_dns_entries(self, domain_name, dns_entries):
        """
        Sets the DnEntries for this Domain, will replace ALL existing dns entries with the new entries

        :param domain_name: the domainName to change the dns entries for
        :param dns_entries: the list of ALL DnsEntries for this domain
        :type domain_name: basestring
        :type dns_entries: list
        """
        cookie = self.build_cookie(mode=MODE_RW, method='setDnsEntries', parameters=[domain_name, dns_entries])
        self.update_cookie(cookie)

        return self.soap_client.service.setDnsEntries(domain_name, dns_entries)


class DnsEntry(SudsObject):
    """
    Representation of a DNS record as expected by the API
    """
    TYPE_A = 'A'
    TYPE_AAAA = 'AAAA'
    TYPE_CNAME = 'CNAME'
    TYPE_MX = 'MX'
    TYPE_NS = 'NS'
    TYPE_TXT = 'TXT'
    TYPE_SRV = 'SRV'

    name = None
    expire = 0
    type = None
    content = None

    def __init__(self, name, expire, record_type, content):
        """
        Constructs a new DnsEntry of the form
        www  IN  86400   A       127.0.0.1
        mail IN  86400   CNAME   @

        Note that the IN class is always mandatory for this Entry and this is implied.

        :param name: the name of this DnsEntry, e.g. www, mail or @
        :param expire: the expiration period of the dns entry, in seconds. For example 86400 for a day
        :param record_type: the type of this entry, one of the TYPE_ constants in this class
        :param content: content of of the dns entry, for example '10 mail', '127.0.0.1' or 'www'
        :type name: basestring
        :type expire: int
        :type record_type: basestring
        :type content: basestring
        """

        # Call the parent __init__
        SudsObject.__init__(self)

        # Assign the fields
        self.name = name
        self.expire = expire
        self.type = record_type
        self.content = content


logging.basicConfig(level=logging.DEBUG)
logging.getLogger('suds.client').setLevel(logging.DEBUG)


def main():
    global module
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            state=dict(default='present', type='str', choices=['present', 'absent']),
            entry=dict(default='update', type='str', choices=['update', 'add']),
            login=dict(required=True, type='str'),
            token=dict(required=True, type='str'),
            domain=dict(required=True, type='str'),
            host=dict(required=True, type='str'),
            expire=dict(required=True, type='int', choices=['60', '300', '3600', '84600']),
            type=dict(required=True, type='str', choices=['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV']),
            content=dict(required=True, type='str'),
            old_content=dict(required=False, type='str'),
        )
    )

    state = module.params.get('state')
    entry = module.params.get('entry')
    domain = module.params.get('domain')
    host_name = module.params.get('host')
    host_expire = module.params.get('expire')
    host_type = module.params.get('type')
    host_content = module.params.get('content')
    old_content = module.params.get('old_content')

    try:
        if host_type == 'A' or host_type == "AAAA":
            ipaddress.ip_address(unicode(host_content))
    except ValueError as e:
        module.fail_json(msg='content %s' % str(e)[1::].replace("'", ""))

    domain_service = DomainService()
    domains = domain_service.get_domain_names()

    if domain not in domains:
        module.fail_json(msg='domain %s is not available in account !' % domain)

    domain_info = domain_service.get_info(domain)

    host_names = []
    current_dns_entries = []
    for item in domain_info.dnsEntries:
        host_names.append(item.name)
        current_dns_entries.append([item.name, item.expire, item.type, item.content])

    new_dns_entry = [host_name, host_expire, host_type, host_content]

    # Add or update DNS entry
    if state == 'present':
        change = False
        dns_entries = []

        for i in xrange(len(current_dns_entries)):
            # Update DNS entry
            if entry == 'update':
                # check if the new hostname is available for updating
                if host_name not in host_names:
                    module.fail_json(msg="hostname %s not found in current DNS records, try to create a new record with: 'entry=add' " % host_name)
                # Check if hostname matches host_name
                if current_dns_entries[i][0] == host_name:
                    # If the record is CNAME, just update the record
                    if current_dns_entries[i][2] == 'CNAME':
                        dns_entries.append(DnsEntry(host_name, host_expire, host_type, host_content))
                        if current_dns_entries[i][1] != host_expire or current_dns_entries[i][3] != host_content:
                            change = True
                    # If the record is non CNAME, check type
                    elif current_dns_entries[i][0] == host_name:
                        if current_dns_entries[i][2] == host_type:
                            # We want to know which record we need to update
                            if current_dns_entries[i][3] == old_content:
                                dns_entries.append(DnsEntry(host_name, host_expire, host_type, host_content))
                                if current_dns_entries[i][1] != host_expire or current_dns_entries[i][3] != host_content:
                                    change = True
                        else:
                            dns_entries.append(DnsEntry(
                                current_dns_entries[i][0],
                                current_dns_entries[i][1],
                                current_dns_entries[i][2],
                                current_dns_entries[i][3])
                            )
                # If the new entry not matches any rules, just add the old values
                else:
                    dns_entries.append(DnsEntry(
                        current_dns_entries[i][0],
                        current_dns_entries[i][1],
                        current_dns_entries[i][2],
                        current_dns_entries[i][3])
                    )

            # Add current DNS entries
            if entry == 'add':
                if current_dns_entries[i][2] == 'CNAME' and current_dns_entries[i][0] == host_name:
                    module.fail_json(msg='You can not have 2 CNAME records for the same hostname !')

                if module.check_mode:
                    module.exit_json(msg='add dns entry', entry=new_dns_entry)

                # Add the current DNS records
                dns_entries.append(DnsEntry(
                    current_dns_entries[i][0],
                    current_dns_entries[i][1],
                    current_dns_entries[i][2],
                    current_dns_entries[i][3])
                )
        # Add the new DNS record here, since we only want to add the record once
        if entry == 'add':
            if current_dns_entries[i][0] != host_name or current_dns_entries[i][1] != host_expire or current_dns_entries[i][2] != host_type or current_dns_entries[i][3] != host_content:
                dns_entries.append(DnsEntry(host_name, host_expire, host_type, host_content))
                change = True

        # If there is a change update the DNS
        if change:
            if module.check_mode:
                new_dns_entries = []
                for item in dns_entries:
                    new_dns_entries.append([item.name, item.expire, item.type, item.content])
                module.exit_json(changed=True, msg='In Check mode: we should update the dns now with %s' % new_dns_entries)
            update_dns = domain_service.set_dns_entries(domain, dns_entries)
            module.exit_json(changed=True, msg='DNS Updated', update=update_dns, updated=new_dns_entry)
        module.exit_json(changed=False, msg='No change in DNS')

    # Remove DNS record:
    if state == 'absent':
        change = False
        dns_entries = []

        for i in xrange(len(current_dns_entries)):
            if current_dns_entries[i][0] == host_name:
                # If type is CNAME there is only one record and we can delete it
                if current_dns_entries[i][2] == 'CNAME':
                    change = True
                # With non 'CNAME' records there can be multiple entries, check content before removing DNS entry
                elif current_dns_entries[i][2] == host_type and current_dns_entries[i][3] == host_content:
                    change = True
                # when DNS record can not be found, add it to the list for update
                else:
                    dns_entries.append(DnsEntry(
                        current_dns_entries[i][0],
                        current_dns_entries[i][1],
                        current_dns_entries[i][2],
                        current_dns_entries[i][3])
                    )
            # If the hostname does not match simply add the DNS entry
            else:
                dns_entries.append(DnsEntry(
                    current_dns_entries[i][0],
                    current_dns_entries[i][1],
                    current_dns_entries[i][2],
                    current_dns_entries[i][3])
                )
        # If there is a change update the DNS
        if change:
            if module.check_mode:
                new_dns_entries = []
                for item in dns_entries:
                    new_dns_entries.append([item.name, item.expire, item.type, item.content])
                module.exit_json(changed=True, msg='In Check mode: we should update the dns now with %s' % new_dns_entries)
            update_dns = domain_service.set_dns_entries(domain, dns_entries)
            module.exit_json(changed=True, msg='DNS Record removed', update=update_dns, removed=new_dns_entry)
        module.exit_json(changed=False, msg='No change in DNS, Entry not found !')

if __name__ == '__main__':
    main()
