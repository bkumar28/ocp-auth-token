# OpenShift API Access Token

### Install dependencies
 ```
  $ pip3 install requests
 ```
###  Edit the `openshift_auth.py` file:
```python
PROTOCOL = "https"                    # or "http"
DOMAINNAME = "openshift.example.com" # your OpenShift domain
PORT = 6443                          # default API port
ocp_username = "admin"
ocp_password = "admin@123"
verify_ssl = False                   # set True if SSL cert trusted

host = f"{PROTOCOL}://api.{DOMAINNAME}:{PORT}"

initial_kwargs = {
    "ocp_username": ocp_username,
    "ocp_password": ocp_password,
    "verify_ssl": verify_ssl,
    "host": host,
}
```
### Usage
Run the script to get your API access token:

 ```
  $ python3 openshift_auth.py
 ```

### Reference
 - Uses requests library for HTTP interactions
 - Inspired by (openshift-restclient-python)[https://github.com/openshift/openshift-restclient-python]
