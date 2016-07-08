# ansible_transip_dns_api
With this ansible module you can add, update and remove TransIP DNS entries.

##### Place python file in libary folder and create a role like
```
.
|-- library
|   `-- transip_dns.py
|-- roles
    `-- transip
        `-- tasks
            `-- main.yml

```
##### Contents of the file roles/transip/tasks/main.yml
```
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
```
##### Enable api
- Make sure you have an account at TransIP
- Enable the API (https://www.transip.nl/cp/mijn-account/#api)
- Add your IP.
- Generate key-pairs
    - Copy-paste the key into a file (transip.key)
    - Generate the rsa key (for now, only unencrypted RSA is supported)
    -     $ openssl rsa -in transip.key -out transip_rsa.key
    - convert the transip_rsa.key to a single line key with newline characters
    -     $ while read line; do printf "%s" "$line\n"; done < transip_rsa.key
    - paste the output quoted into the token value field

##### Original code for python TransIP api can be found here:
https://github.com/mhogerheijde/transip-api
