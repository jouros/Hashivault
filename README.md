# Hashivault

In this demo lab I will focus on Kubernetes integration for Hashicorp Vault, this is not production ready deployment e.g. secrets persistent storage is not configured. 

This demo is installed on WSL2 and I'll restart Vault every time I continue, so Tokens etc. will recreated every time. 

I have deployed Hashivault with Ubuntu cloud init and it create 'vault' regular user account for all localhost root token Vault admin operations. For remote management I use Approle Token with limited permissions, I'll call that 'DevOps admin' user or host. Third 'user' is Kubernetes which has 'read only' permissions for 'DevOps admin' secrets.  

For Ansible I have deployed 'management' user account with sudo, see example below: 

```text
management@hashivault:~$ sudo su
root@hashivault:/home/management# su vault
vault@hashivault:/home/management$ cd
vault@hashivault:~$ pwd
/home/vault
vault@hashivault:~$ id
uid=1001(vault) gid=1002(vault) groups=1002(vault),100(users)
```

Preparing hashi repo for Ubuntu cloudimage seed config:
```text
wget https://apt.releases.hashicorp.com/gpg -O hashi.key
gpg --list-packets hashi.key | awk '/keyid:/{ print $2 }'
AA16FCBCA621E701
706E668369C085E9
```

## Test Vault in Dev mode

Dev Mode run in shell foreground:
```text
vault@hashivault:~$ vault server -dev
==> Vault server configuration:

Administrative Namespace:
             Api Address: http://127.0.0.1:8200
                     Cgo: disabled
         Cluster Address: https://127.0.0.1:8201
   Environment Variables: GODEBUG, GOTRACEBACK, HOME, LANG, LESSCLOSE, LESSOPEN, LOGNAME, LS_COLORS, MAIL, OLDPWD, PATH, PWD, SHELL, SHLVL, SUDO_COMMAND, SUDO_GID, SUDO_UID, SUDO_USER, TERM, USER, _
              Go Version: go1.21.4
              Listener 1: tcp (addr: "127.0.0.1:8200", cluster address: "127.0.0.1:8201", max_request_duration: "1m30s", max_request_size: "33554432", tls: "disabled")
               Log Level:
                   Mlock: supported: true, enabled: false
           Recovery Mode: false
                 Storage: inmem
                 Version: Vault v1.15.4, built 2023-12-04T17:45:28Z
             Version Sha: 9b61934559ba31150860e618cf18e816cbddc630

==> Vault server started! Log data will stream in below:
LOGS HERE
WARNING! dev mode is enabled! In this mode, Vault runs entirely in-memory
and starts unsealed with a single unseal key. The root token is already
authenticated to the CLI, so you can immediately begin using Vault.

You may need to set the following environment variables:

    $ export VAULT_ADDR='http://127.0.0.1:8200'

The unseal key and root token are displayed below in case you want to
seal/unseal the Vault or re-authenticate.

Unseal Key: YsTbXCBD9vLzCE6dN6g3lX28Xr7CB2lku+LGeyowq/4=
Root Token: hvs.CMHQAeX563xOfxRgf6WnmhON

Development mode should NOT be used in production installations!
```

In another login session:
```text
vault@hashivault:~$ export VAULT_ADDR='http://127.0.0.1:8200'
vault@hashivault:~$ vault status
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    1
Threshold       1
Version         1.15.4
Build Date      2023-12-04T17:45:28Z
Storage Type    inmem
Cluster Name    vault-cluster-aad050ce
Cluster ID      2c6d6bbb-51cc-acae-a86c-3202c82dc493
HA Enabled      false
```

Test key - value secret storage: 
```text
vault@hashivault:~$ vault secrets list
Path          Type         Accessor              Description
----          ----         --------              -----------
cubbyhole/    cubbyhole    cubbyhole_408fa64b    per-token private secret storage
identity/     identity     identity_c8e66249     identity store
secret/       kv           kv_c81e1164           key/value secret storage
sys/          system       system_dccc7b95       system endpoints used for control, policy and debugging
vault@hashivault:~$ vault kv put secret/testsecret testvalue=pancake
===== Secret Path =====
secret/data/testsecret

======= Metadata =======
Key                Value
---                -----
created_time       2024-01-26T10:17:55.557951835Z
custom_metadata    <nil>
deletion_time      n/a
destroyed          false
version            1
vault@hashivault:~$ vault kv get secret/testsecret
===== Secret Path =====
secret/data/testsecret

======= Metadata =======
Key                Value
---                -----
created_time       2024-01-26T10:17:55.557951835Z
custom_metadata    <nil>
deletion_time      n/a
destroyed          false
version            1

====== Data ======
Key          Value
---          -----
testvalue    pancake
```

Important things to notice at this point:
```text
'Seal Type       shamir' Seal type Shamir means that 'Unseal Key' is split into 'Total Shares' amount of keys. In Dev mode only only one key. 
'Total Shares    1'      How many parts 'Unseal Key' has
'Unseal Key'             Key to open Vault before serving requests                 
'Root Token'             root authentication token         
'Initialized     true'   Vault has started
'Sealed          false'  Vault secrets are in system memory and available for requests
```

Vault remote web browser UI test from WSL2 Ubuntu, first lets install Firefox, WSL2 has direct X support:
```text
# snap install firefox
firefox 122.0-2 from Mozilla✓ installed
$ firefox &
```

Vault is listening localhost, so lets have a redirect: 
```
$ socat TCP4-L:8300,fork,reuseaddr TCP4:127.0.0.1:8200
```

After above steps you can open Vault GUI from Firefox browser and log in using root token.


## Configure Vault 

/etc/vault.d/vault.hcl:
```text
# cat vault.hcl
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# Full configuration options can be found at https://developer.hashicorp.com/vault/docs/configuration

ui = true
disable_clustering = true
api_addr           = "https://102.168.122.14:8200"

#mlock = true
#disable_mlock = true

storage "file" {
  path = "/opt/vault/data"
}

#storage "consul" {
#  address = "127.0.0.1:8500"
#  path    = "vault"
#}

# HTTP listener
listener "tcp" {
  address       = "127.0.0.1:8200"
  tls_disable   = 1
}

# HTTPS listener
listener "tcp" {
  address       = "192.168.122.14:8200"
  tls_cert_file = "/opt/vault/tls/custom.crt"
  tls_key_file  = "/opt/vault/tls/custom.key"
  tls_min_version = "tls12"
  tls_client_ca_file = "/opt/vault/tls/rootCA.crt"
  telemetry {
    unauthenticated_metrics_access = "true"
  }
}

# Enterprise license_path
# This will be required for enterprise as of v1.8
#license_path = "/etc/vault.d/vault.hclic"

# Example AWS KMS auto unseal
#seal "awskms" {
#  region = "us-east-1"
#  kms_key_id = "REPLACE-ME"
#}

# Example HSM auto unseal
#seal "pkcs11" {
#  lib            = "/usr/vault/lib/libCryptoki2_64.so"
#  slot           = "0"
#  pin            = "AAAA-BBBB-CCCC-DDDD"
#  key_label      = "vault-hsm-key"
#  hmac_key_label = "vault-hsm-hmac-key"
#}
```


```text
$ openssl x509 -in custom.crt -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5b:a9:68:65:1d:f4:ea:a1:1e:10:d3:15:bc:7f:1a:6d:17:7a:06:38
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = hashivault.jrc.local, C = FI, L = HELSINKI
        Validity
            Not Before: Jan 29 13:36:37 2024 GMT
            Not After : Jan 27 13:36:37 2029 GMT
        Subject: C = FI, ST = Helsinki, L = Helsinki, O = jrc, OU = jrc, CN = hashivault.jrc.local
```

Crt and Key files are copied into /opt/vault/tls:
```text
/opt/vault/tls# ls -la
total 32
drwx------ 3 vault vault 4096 Jan 29 17:34 .
drwxr-xr-x 4 vault vault 4096 Jan 17 16:27 ..
drwxr-xr-x 3 root  root  4096 Jan 17 16:27 .cache
-rw------- 1 vault vault 2082 Jan 29 15:36 custom.crt
-rw------- 1 vault vault 3268 Jan 29 15:35 custom.key
-rw------- 1 vault vault 1923 Jan 29 15:35 rootCA.crt
-rw------- 1 vault vault 1850 Jan 17 16:27 tls.crt
-rw------- 1 vault vault 3272 Jan 17 16:27 tls.key
```

## Start Vault

Start Vault: 

```text
# systemctl start vault
# systemctl enable vault
# systemctl status vault --no-pager
● vault.service - "HashiCorp Vault - A tool for managing secrets"
     Loaded: loaded (/lib/systemd/system/vault.service; enabled; vendor preset: enabled)
     Active: active (running) since Mon 2024-01-29 17:36:09 EET; 12min ago
       Docs: https://developer.hashicorp.com/vault/docs
   Main PID: 8867 (vault)
      Tasks: 7 (limit: 1101)
     Memory: 96.0M
        CPU: 351ms
     CGroup: /system.slice/vault.service
             └─8867 /usr/bin/vault server -config=/etc/vault.d/vault.hcl

Jan 29 17:36:09 hashivault vault[8867]: ==> Vault server started! Log data will stream in below:
Jan 29 17:36:09 hashivault vault[8867]: 2024-01-29T17:36:09.805+0200 [INFO]  proxy environment: http_proxy="" https_proxy="" no_proxy=""
Jan 29 17:36:09 hashivault vault[8867]: 2024-01-29T17:36:09.805+0200 [INFO]  incrementing seal generation: generation=1
Jan 29 17:36:09 hashivault vault[8867]: 2024-01-29T17:36:09.832+0200 [INFO]  core: Initializing version history cache for core
Jan 29 17:36:09 hashivault vault[8867]: 2024-01-29T17:36:09.832+0200 [INFO]  events: Starting event system
Jan 29 17:36:09 hashivault systemd[1]: Started "HashiCorp Vault - A tool for managing secrets".
Jan 29 17:40:44 hashivault vault[8867]: 2024-01-29T17:40:44.210+0200 [INFO]  core: security barrier not initialized
Jan 29 17:40:44 hashivault vault[8867]: 2024-01-29T17:40:44.210+0200 [INFO]  core: seal configuration missing, not initialized
Jan 29 17:41:54 hashivault vault[8867]: 2024-01-29T17:41:54.167+0200 [INFO]  core: security barrier not initialized
Jan 29 17:41:54 hashivault vault[8867]: 2024-01-29T17:41:54.168+0200 [INFO]  core: seal configuration missing, not initialized
#
#  netstat -anp -A inet | grep 8200
tcp        0      0 127.0.0.1:8200          0.0.0.0:*               LISTEN      8867/vault
tcp        0      0 192.168.122.14:8200     0.0.0.0:*               LISTEN      8867/vault
```

Network test with curl:
```text
$ curl -k https://192.168.122.14:8200/v1/sys/seal-status
{"type":"shamir","initialized":false,"sealed":true,"t":0,"n":0,"progress":0,"nonce":"","version":"1.15.4","build_date":"2023-12-04T17:45:28Z","migration":false,"recovery_seal":false,"storage_type":"file"}
$ curl --cacert rootCA.crt 'https://192.168.122.14:8200/v1/sys/seal-status'
{"type":"shamir","initialized":false,"sealed":true,"t":0,"n":0,"progress":0,"nonce":"","version":"1.15.4","build_date":"2023-12-04T17:45:28Z","migration":false,"recovery_seal":false,"storage_type":"file"}
```

In my vault.hcl config I have both http and https listeners configured, http I'm going to use internally to localhost and https from outside:
```
vault@hashivault:~$ id
uid=1001(vault) gid=1002(vault) groups=1002(vault),100(users)
vault@hashivault:~$ export VAULT_ADDR="http://127.0.0.1:8200"
vault@hashivault:~$ echo $VAULT_ADDR
http://127.0.0.1:8200
vault@hashivault:~$ vault status
Key                Value
---                -----
Seal Type          shamir
Initialized        false
Sealed             true
Total Shares       0
Threshold          0
Unseal Progress    0/0
Unseal Nonce       n/a
Version            1.15.4
Build Date         2023-12-04T17:45:28Z
Storage Type       file
HA Enabled         false
vault@hashivault:~$ export VAULT_ADDR="https://192.168.122.14:8200"
vault@hashivault:~$ echo $VAULT_ADDR
https://192.168.122.14:8200
vault@hashivault:~$ vault status -ca-path=/opt/vault/tls/rootCA.crt
Key                Value
---                -----
Seal Type          shamir
Initialized        false
Sealed             true
Total Shares       0
Threshold          0
Unseal Progress    0/0
Unseal Nonce       n/a
Version            1.15.4
Build Date         2023-12-04T17:45:28Z
Storage Type       file
HA Enabled         false
```

## Initialize Vault

Check Vault status:
```text
$ vault operator init -status
Vault is not initialized
```

I'll initialize Vault with three key shares, which mean that unseal key is split into three parts. Key treshold mean how many key parts is needed to construct root key:
```text
$ vault operator init -key-shares=3 -key-threshold=2
Unseal Key 1: 5PNLW3Sx...
Unseal Key 2: lC7c2nHi...
Unseal Key 3: 81wkeXM1...

Initial Root Token: hvs.XVc...

Vault initialized with 3 key shares and a key threshold of 2. Please securely
distribute the key shares printed above. When the Vault is re-sealed,
restarted, or stopped, you must supply at least 2 of these keys to unseal it
before it can start servicing requests.

Vault does not store the generated root key. Without at least 2 keys to
reconstruct the root key, Vault will remain permanently sealed!

It is possible to generate new unseal keys, provided you have a quorum of
existing unseal keys shares. See "vault operator rekey" for more information.
```

Check Vault status again:
```text
$ vault operator init -status
Vault is initialized
```

## Unseal Vault for allowing its use

In the beginning Vault is sealed:
```text
$ vault status
Key                Value
---                -----
Seal Type          shamir
Initialized        true
Sealed             true
Total Shares       3
Threshold          2
Unseal Progress    0/2
Unseal Nonce       n/a
Version            1.15.4
Build Date         2023-12-04T17:45:28Z
Storage Type       file
HA Enabled         false
```

Unseal with two keys and notice 'Unseal Progress' info:
```text
$ vault operator unseal
Unseal Key (will be hidden):
Key                Value
---                -----
Seal Type          shamir
Initialized        true
Sealed             true
Total Shares       3
Threshold          2
Unseal Progress    1/2
Unseal Nonce       4ab073a0-dc53-c347-a480-d4baa37db660
Version            1.15.4
Build Date         2023-12-04T17:45:28Z
Storage Type       file
HA Enabled         false
```

Again with second key:
```text
$ vault operator unseal
Unseal Key (will be hidden):
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    3
Threshold       2
Version         1.15.4
Build Date      2023-12-04T17:45:28Z
Storage Type    file
Cluster Name    vault-cluster-09fa5d16
Cluster ID      72fb83bd-8e20-3a2b-f874-1ed68a197c50
HA Enabled      false
```
Above unseal step have to done every time Vault is restarted. 

In my demo Lab Vault is using default file backend srorage, do not use file storage for any serious use. If you want file backend, you can use raft which has ommand for taking snapshot of storage for backup. My config is just for testing Vault integration to K8s:
```text
In /etc/vault.d/vault.hcl:
storage "file" {
  path = "/opt/vault/data"
}

$ ls -la /opt/vault/data/
total 20
drwxr-xr-x 5 vault vault 4096 Jan 30 13:12 .
drwxr-xr-x 4 vault vault 4096 Jan 17 16:27 ..
drwx------ 6 vault vault 4096 Jan 30 13:31 core
drwx------ 3 vault vault 4096 Jan 30 13:12 logical
drwx------ 4 vault vault 4096 Jan 30 13:12 sys
```

## Test remote Vault login with root token

```text
# curl -fsSL https://apt.releases.hashicorp.com/gpg | apt-key add -
# apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
# apt update
# apt install -y vault
# vault --version
Vault v1.15.4 (9b61934559ba31150860e618cf18e816cbddc630), built 2023-12-04T17:45:28Z
$ export VAULT_ADDR="https://192.168.122.14:8200"
$ echo $VAULT_ADDR
https://192.168.122.14:8200
$ vault login -ca-path=./rootCA.crt
Token (will be hidden):
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                  Value
---                  -----
token                hvs.XVc0QbzWH0wLrCQTu2spWA28
token_accessor       6rvQaRyeE6drZbeuQGFnAUzQ
token_duration       ∞
token_renewable      false
token_policies       ["root"]
identity_policies    []
policies             ["root"]
```

Above login will store credential here:
```text
$ cat ~/.vault-token
hvs.XVc0QbzW...
```

After login credentials are stored in a file, so they are not requested for next cmd. Lets change output format for remote connection to separate remote and local operations:
```text
$ export VAULT_FORMAT="json"
$ echo $VAULT_FORMAT
json
$ vault status -ca-path=./rootCA.crt
{
  "type": "shamir",
  "initialized": true,
  "sealed": false,
  "t": 2,
  "n": 3,
  "progress": 0,
  "nonce": "",
  "version": "1.15.4",
  "build_date": "2023-12-04T17:45:28Z",
  "migration": false,
  "cluster_name": "vault-cluster-09fa5d16",
  "cluster_id": "72fb83bd-8e20-3a2b-f874-1ed68a197c50",
  "recovery_seal": false,
  "storage_type": "file",
  "ha_enabled": false,
  "active_time": "0001-01-01T00:00:00Z"
}
```

## Vault KV secrets engine V2

Enable V2 secrets Key - Value- engine. V2 means that secrets will have version history you can revert to:
```text
$ vault secrets list
Path          Type         Accessor              Description
----          ----         --------              -----------
cubbyhole/    cubbyhole    cubbyhole_4ffe3caa    per-token private secret storage
identity/     identity     identity_ec902b7d     identity store
sys/          system       system_d4b28570       system endpoints used for control, policy and debugging
$
$ vault secrets enable -version=2 -path=devops/ kv
Success! Enabled the kv secrets engine at: devops/
$
$ vault secrets list
Path          Type         Accessor              Description
----          ----         --------              -----------
cubbyhole/    cubbyhole    cubbyhole_4ffe3caa    per-token private secret storage
devops/       kv           kv_dfdf5534           n/a
identity/     identity     identity_ec902b7d     identity store
sys/          system       system_d4b28570       system endpoints used for control, policy and debugging
```


Lets store kv foo=a, change that with foo=b, read current value (b) and read value from version=1 (a):
```text
$ vault kv put -mount=devops mysecret foo=a
==== Secret Path ====
devops/data/mysecret

======= Metadata =======
Key                Value
---                -----
created_time       2024-01-31T12:43:17.831300231Z
custom_metadata    <nil>
deletion_time      n/a
destroyed          false
version            1
$
$ vault kv get -mount=devops mysecret
==== Secret Path ====
devops/data/mysecret

======= Metadata =======
Key                Value
---                -----
created_time       2024-01-31T12:43:17.831300231Z
custom_metadata    <nil>
deletion_time      n/a
destroyed          false
version            1

=== Data ===
Key    Value
---    -----
foo    a
$
$ vault kv put -mount=devops mysecret foo=b
==== Secret Path ====
devops/data/mysecret

======= Metadata =======
Key                Value
---                -----
created_time       2024-01-31T12:45:14.575189063Z
custom_metadata    <nil>
deletion_time      n/a
destroyed          false
version            2
$
$ vault kv get -mount=devops mysecret
==== Secret Path ====
devops/data/mysecret

======= Metadata =======
Key                Value
---                -----
created_time       2024-01-31T12:45:14.575189063Z
custom_metadata    <nil>
deletion_time      n/a
destroyed          false
version            2

=== Data ===
Key    Value
---    -----
foo    b
$
$ vault kv get -mount=devops -version=1 mysecret
==== Secret Path ====
devops/data/mysecret

======= Metadata =======
Key                Value
---                -----
created_time       2024-01-31T12:43:17.831300231Z
custom_metadata    <nil>
deletion_time      n/a
destroyed          false
version            1

=== Data ===
Key    Value
---    -----
foo    a
```


## Configure Vault Policy and auth method

In previous example, real path for mysecret is `devops/data/mysecret`. Lets create policy for DevOps Admin with permissions to read, update, delete, create and list secrets:

```text
$ cat /etc/vault.d/policy1.hcl
path "devops/data/project1/*" {
  capabilities = ["read", "update", "delete", "create", "list"]
}

path "devops/data/mysecret" {
  capabilities = ["read"]
}
$
$ vault policy write devopsadmin /etc/vault.d/policy1.hcl
Success! Uploaded policy: devopsadmin
$
$ vault policy list
default
devopsadmin
root
$
$ vault policy read devopsadmin
path "devops/data/project1/*" {
  capabilities = ["read", "update", "delete", "create", "list"]
}

path "devops/data/mysecret" {
  capabilities = ["read"]
}
```

Approle is role that allows machines or apps to authenticate with vault roles. For this role I can allow access based on token for which I can give time to live and renew time to live parameters which means I have full control of time period for which I allow secrets modification. In this case I will use approle for DevOps admin user for fine-grained access control. 

Next I'll create Approle:
```text
$ vault auth list
Path      Type     Accessor               Description                Version
----      ----     --------               -----------                -------
token/    token    auth_token_751e8ae6    token based credentials    n/a
$
$ vault auth enable -path=devops/ -description="DevOps Admin credentials" approle
Success! Enabled approle auth method at: devops/
$
$ vault auth list
Path       Type       Accessor                 Description                 Version
----       ----       --------                 -----------                 -------
devops/    approle    auth_approle_c0473ce8    DevOps Admin credentials    n/a
token/     token      auth_token_751e8ae6      token based credentials     n/a
```

Here I set token TTL 2h, max renewal time 6h for created role 'devopsadminrole' and bind it to 'devopsadmin' policy:
```text
$ vault write auth/devops/role/devopsadminrole token_policies="devopsadmin" token_ttl=2h token-max_ttl=6h
Success! Data written to: auth/devops/role/devopsadminrole
$
$ vault list auth/devops/role
Keys
----
devopsadminrole
$
$ vault read auth/devops/role/devopsadminrole
Key                        Value
---                        -----
bind_secret_id             true
local_secret_ids           false
secret_id_bound_cidrs      <nil>
secret_id_num_uses         0
secret_id_ttl              0s
token_bound_cidrs          []
token_explicit_max_ttl     0s
token_max_ttl              0s
token_no_default_policy    false
token_num_uses             0
token_period               0s
token_policies             [devopsadmin]
token_ttl                  2h
token_type                 default
$
$ vault read auth/devops/role/devopsadminrole/role-id
Key        Value
---        -----
role_id    2e697b26-4cef-9e6f-e304-07237997ed08

Add ip access control list to role, I'll add remote devOps admin host and Vault local ip to access control list:
```text
$ vault write auth/devops/role/devopsadminrole/secret-id cidr_list=192.168.122.14/32,172.18.119.21/32,127.0.0.1/32
Key                   Value
---                   -----
secret_id             e50ba2b6-d14d-9ebb-5d4a-ef93699fb375
secret_id_accessor    907d4ff0-fdc8-0573-164f-c02d201ce8e2
secret_id_num_uses    0
secret_id_ttl         0s
```

I'll do vault managemetn oprerations from Vault localhost, so I'll haveto allow local addresses also. If I forget to do that, I'll get:
```text
 source address "127.0.0.1" unauthorized through CIDR restrictions on the secret ID
```

Next I'll create access token, now I'll have to talk to correct ip addr and use ssl: 
```text
$ export VAULT_ADDR="https://192.168.122.14:8200"
$
$ vault write -ca-path=/opt/vault/tls/rootCA.crt auth/devops/login role_id="2e697b26-4cef-9e6f-e304-07237997ed08" secret_id="e50ba2b6-d14d-9ebb-5d4a-ef93699fb375"
Key                     Value
---                     -----
token                   hvs.CAESINItjQ5I64Nhg-gVuxn61XsRfPWRouDGcNCGlhMEJDkaGh4KHGh2cy5wUTRoNW9VaUdaQUFwR3haZ2gybHRLU28
token_accessor          zPu7urYKlR3oQtzeCIOU5GzP
token_duration          2h
token_renewable         true
token_policies          ["default" "devopsadmin"]
identity_policies       []
policies                ["default" "devopsadmin"]
token_meta_role_name    devopsadminrole
```

Above we have our token which is valid for 2h and can be renewed until 6h, lets have remote connection with new token:
```text
$ rm ~/.vault-token
$
$ vault login -ca-cert rootCA.crt
Token (will be hidden):
{
  "request_id": "",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": null,
  "warnings": null,
  "auth": {
    "client_token": "hvs.CAESINItjQ5I64Nhg-gVuxn61XsRfPWRouDGcNCGlhMEJDkaGh4KHGh2cy5wUTRoNW9VaUdaQUFwR3haZ2gybHRLU28",
    "accessor": "zPu7urYKlR3oQtzeCIOU5GzP",
    "policies": [
      "default",
      "devopsadmin"
    ],
    "token_policies": [
      "default",
      "devopsadmin"
    ],
    "identity_policies": null,
    "metadata": {
      "role_name": "devopsadminrole"
    },
    "orphan": false,
    "entity_id": "",
    "lease_duration": 6671,
    "renewable": true,
    "mfa_requirement": null
  }
}
```

Policy for this role was 'read' for mysecret which was set earlier, lets try to read it:
```
$ vault kv get -ca-cert rootCA.crt -mount=devops mysecret
{
  "request_id": "9aa85123-f866-ecea-49a6-8cea537221e1",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "data": {
      "foo": "b"
    },
    "metadata": {
      "created_time": "2024-01-31T12:45:14.575189063Z",
      "custom_metadata": null,
      "deletion_time": "",
      "destroyed": false,
      "version": 2
    }
  },
  "warnings": null
}
```

Read was successfule as expected, lets try to change value which was not allowed operation:
```text
$ vault kv put -ca-cert rootCA.crt -mount=devops mysecret foo=c
Error writing data to devops/data/mysecret: Error making API request.

URL: PUT https://192.168.122.14:8200/v1/devops/data/mysecret
Code: 403. Errors:

* 1 error occurred:
        * permission denied
```

Permission was denied as expected. Lets create new secret, read and update value: 
```text
$ vault kv put -ca-cert rootCA.crt -mount=devops/ project1/secret1 foo=bar
{
  "request_id": "4877ce61-5594-a1a2-edda-534995f594f0",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "created_time": "2024-02-01T14:25:22.082848656Z",
    "custom_metadata": null,
    "deletion_time": "",
    "destroyed": false,
    "version": 1
  },
  "warnings": null
}
$
$ vault kv get -ca-cert rootCA.crt -mount=devops/ project1/secret1
{
  "request_id": "ee6800e3-d6fb-bcde-1c78-7d09bb60867a",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "data": {
      "foo": "bar"
    },
    "metadata": {
      "created_time": "2024-02-01T14:25:22.082848656Z",
      "custom_metadata": null,
      "deletion_time": "",
      "destroyed": false,
      "version": 1
    }
  },
  "warnings": null
}
$ vault kv put -ca-cert rootCA.crt -mount=devops/ project1/secret1 foo=barbar
{
  "request_id": "aecdc4b3-cb04-c4e1-853b-a0b46025891e",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "created_time": "2024-02-01T14:30:16.720983737Z",
    "custom_metadata": null,
    "deletion_time": "",
    "destroyed": false,
    "version": 2
  },
  "warnings": null
}
$
$ vault kv get -ca-cert rootCA.crt -mount=devops/ project1/secret1
{
  "request_id": "9276d89b-be09-178f-8b5c-ab7a0620add8",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "data": {
      "foo": "barbar"
    },
    "metadata": {
      "created_time": "2024-02-01T14:30:16.720983737Z",
      "custom_metadata": null,
      "deletion_time": "",
      "destroyed": false,
      "version": 2
    }
  },
  "warnings": null
}
$
$ vault kv put -ca-cert rootCA.crt -mount=devops/ project1/secret2 something=true
{
  "request_id": "676826a9-f64c-2537-8234-c51cc0529349",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "created_time": "2024-02-01T14:31:30.207742616Z",
    "custom_metadata": null,
    "deletion_time": "",
    "destroyed": false,
    "version": 1
  },
  "warnings": null
}
$
$ vault kv get -ca-cert rootCA.crt -mount=devops/ project1/secret2
{
  "request_id": "4aaf35e4-84cd-cf56-8da1-87c5a930842d",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "data": {
      "something": "true"
    },
    "metadata": {
      "created_time": "2024-02-01T14:31:30.207742616Z",
      "custom_metadata": null,
      "deletion_time": "",
      "destroyed": false,
      "version": 1
    }
  },
  "warnings": null
}
```

For being able to list all secrets in a path, I'll have make metadata addition to policy:
```text
path "devops/metadata/project1/*" {
  capabilities = ["list", "delete"]
}
$
$ vault policy write devopsadmin /etc/vault.d/policy1.hcl
$
$ vault kv list -ca-cert rootCA.crt -mount=devops/ project1
[
  "secret1",
  "secret2"
]
```

I did not do Vault managemtn for a while and Token TTL is done, so lets re-create Token. Steps are 1) check role_id 2) bind access control cidr_list to secret_id 3) bind login to role_id and secret_id to get Token:
```text
$ vault list auth/devops/role/
Keys
----
devopsadminrole
$
$ vault read auth/devops/role/devopsadminrole/role-id
Key        Value
---        -----
role_id    2e697b26-4cef-9e6f-e304-07237997ed08
$
$ vault write auth/devops/role/devopsadminrole/secret-id cidr_list=192.168.122.14/32,172.18.119.21/32,127.0.0.1/32
Key                   Value
---                   -----
secret_id             23254025-babf-7a82-4685-1fa494b4c2b6
secret_id_accessor    0d58887b-fee5-9a14-3397-b0562dea3b43
secret_id_num_uses    0
secret_id_ttl         0s
$
$ vault write auth/devops/login role_id="2e697b26-4cef-9e6f-e304-07237997ed08" secret_id="e63087b4-3673-0b7e-79c0-feb811b776c9"
Key                     Value
---                     -----
token                   hvs.CAESIPSx00_OvrhD1Tt71QAfMSXC9ZX_B8GvoEc6_kTkdGcdGh4KHGh2cy5WNmJET2NreVhJejZsbDdOWU12bHFxOWs
token_accessor          gWlNqyuVCZW4hgRngkzisu9Y
token_duration          2h
token_renewable         true
token_policies          ["default" "devopsadmin"]
identity_policies       []
policies                ["default" "devopsadmin"]
token_meta_role_name    devopsadminrole
```

Next step is remote login from devops host with selfsigned cert:
```text
$ export VAULT_ADDR="https://192.168.122.14:8200"
$
$ vault login -ca-cert rootCA.crt
Token (will be hidden):
Success! You are now authenticated. The token information displayed below
is already stored in the token helper. You do NOT need to run "vault login"
again. Future Vault requests will automatically use this token.

Key                     Value
---                     -----
token                   hvs.CAESIPSx00_OvrhD1Tt71QAfMSXC9ZX_B8GvoEc6_kTkdGcdGh4KHGh2cy5WNmJET2NreVhJejZsbDdOWU12bHFxOWs
token_accessor          gWlNqyuVCZW4hgRngkzisu9Y
token_duration          1h53m33s
token_renewable         true
token_policies          ["default" "devopsadmin"]
identity_policies       []
policies                ["default" "devopsadmin"]
token_meta_role_name    devopsadminrole
```

Now devops admin has new 2h TTL Token, lets continue policy verification with delete value from secret2:
```text
$ vault kv delete -ca-cert rootCA.crt -mount=devops/ project1/secret2
Success! Data deleted (if it existed) at: devops/data/project1/secret2
$
$ vault kv get -ca-cert rootCA.crt -mount=devops/data/ project1/secret2
======== Secret Path ========
devops/data/project1/secret2

======= Metadata =======
Key                Value
---                -----
created_time       2024-02-01T14:31:30.207742616Z
custom_metadata    <nil>
deletion_time      2024-02-02T13:35:47.919760392Z
destroyed          false
version            1
$
```

Operation was successful, but secret2 still exist, it just doesn't have data anymore:
```text
$ vault kv list -ca-cert rootCA.crt -mount=devops/ project1
Keys
----
secret1
secret2
```

To completely remove secret2 I'll have to:
```text
$  vault kv metadata delete -ca-cert rootCA.crt -mount=devops/ project1/secret2
Success! Data deleted (if it existed) at: devops/metadata/project1/secret2
$
$ vault kv list -ca-cert rootCA.crt -mount=devops/ project1
Keys
----
secret1
```

My Python APP is expecting data.json, which mean we have to delete previous kv test values and put data.json into its place:
```text
$ vault kv delete -ca-cert rootCA.crt -mount=devops/data/ project1/secret1
Success! Data deleted (if it existed) at: devops/data/project1/secret1
$
$ vault write -ca-cert rootCA.crt devops/data/project1/secret1 @data.json
Key                Value
---                -----
created_time       2024-02-07T13:53:42.269491428Z
custom_metadata    <nil>
deletion_time      n/a
destroyed          false
version            3
$
$ vault kv get -ca-cert ../SSL/rootCA.crt -mount=devops/data/ project1/secret1
{
  "request_id": "393b6da1-be32-7b87-0155-833495994143",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "data": {
      "password": "correct_password",
      "username": "correct_user"
    },
    "metadata": {
      "created_time": "2024-02-07T13:53:42.269491428Z",
      "custom_metadata": null,
      "deletion_time": "",
      "destroyed": false,
      "version": 3
    }
  },
  "warnings": null
}
```


### Approle operations

How to check how long time Token still has before expiration:
```tect
$ vault token lookup -accessor gWlNqyuVCZW4hgRngkzisu9Y
Key                 Value
---                 -----
accessor            gWlNqyuVCZW4hgRngkzisu9Y
creation_time       1706880248
creation_ttl        2h
display_name        devops
entity_id           8288e91e-31aa-f709-2718-68957cb54ba5
expire_time         2024-02-02T17:24:08.883802366+02:00
explicit_max_ttl    0s
id                  n/a
issue_time          2024-02-02T15:24:08.883804347+02:00
meta                map[role_name:devopsadminrole]
num_uses            0
orphan              true
path                auth/devops/login
policies            [default devopsadmin]
renewable           true
ttl                 16m20s
type                service
```

Time was 17:09 and expire time 17:24, so I still have about 15 minutes for Token renewal before Token is lost, Token has to renewed before it expires with `vault token renew -accessor xxxxx`

To operate with secret id we have to use accessor, my current secret_id is referenced with `secret_id_accessor edbf5a51-dd47-a45e-c678-1adb9af005d0`, below I list accessors, get info about current secret_id and remove old:
```text
$ vault list auth/devops/role/devopsadminrole/secret-id
Keys
----
0d58887b-fee5-9a14-3397-b0562dea3b43
907d4ff0-fdc8-0573-164f-c02d201ce8e2
edbf5a51-dd47-a45e-c678-1adb9af005d0
$
$ vault write auth/devops/role/devopsadminrole/secret-id-accessor/lookup secret_id_accessor=edbf5a51-dd47-a45e-c678-1adb9af005d0
Key                   Value
---                   -----
cidr_list             [192.168.122.14/32 172.18.119.21/32 127.0.0.1/32]
creation_time         2024-02-02T15:22:15.47628367+02:00
expiration_time       0001-01-01T00:00:00Z
last_updated_time     2024-02-02T15:22:15.47628367+02:00
metadata              map[]
secret_id_accessor    edbf5a51-dd47-a45e-c678-1adb9af005d0
secret_id_num_uses    0
secret_id_ttl         0s
token_bound_cidrs     []
$
$ vault write auth/devops/role/devopsadminrole/secret-id-accessor/destroy secret_id_accessor=907d4ff0-fdc8-0573-164f-c02d201ce8e2
Success! Data written to: auth/devops/role/devopsadminrole/secret-id-accessor/destroy
$
$ vault write auth/devops/role/devopsadminrole/secret-id-accessor/destroy secret_id_accessor=0d58887b-fee5-9a14-3397-b0562dea3b43
Success! Data written to: auth/devops/role/devopsadminrole/secret-id-accessor/destroy
$
$ vault list auth/devops/role/devopsadminrole/secret-id
Keys
----
edbf5a51-dd47-a45e-c678-1adb9af005d0
```

## Kubernetes Sidecar Agent injector

Finally after very long introduction to the main point, how to integrate Kubernetes Pod secrets management to Hashi Vault. In my lab I'll use Sidecar Agent Injector. 

First I need to add Hashicorp Helm repo for which I use Ansible role 'helm-addrepo' from WSL2Fun:
```text
$ ansible-playbook main.yml --tags "helm-addrepo"
ok: [kube1] =>
  msg: |-
    NAME            URL
    bitnami         https://charts.bitnami.com/bitnami
    custom-repo     https://jouros.github.io/helm-repo
    hashicorp       https://helm.releases.hashicorp.com
```

Info from K8s:
```text
$ k get mutatingwebhookconfigurations -n test2
NAME                           WEBHOOKS   AGE
vault-k8s-agent-injector-cfg   1          122m
$
$ k get mutatingwebhookconfigurations vault-k8s-agent-injector-cfg -n test2 -o yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  annotations:
    meta.helm.sh/release-name: vault-k8s
    meta.helm.sh/release-namespace: test2
  creationTimestamp: "2024-02-13T11:32:13Z"
  generation: 2
  labels:
    app.kubernetes.io/instance: vault-k8s
    app.kubernetes.io/managed-by: Helm
    app.kubernetes.io/name: vault-agent-injector
  name: vault-k8s-agent-injector-cfg
...
```

### Vault configuration for Kubernetes

First I'll enable kubernetes auth method:
```text
$ vault auth list
Path       Type       Accessor                 Description                 Version
----       ----       --------                 -----------                 -------
devops/    approle    auth_approle_c0473ce8    DevOps Admin credentials    n/a
token/     token      auth_token_751e8ae6      token based credentials     n/a
$
$ vault auth enable kubernetes
Success! Enabled kubernetes auth method at: kubernetes/
$
$ vault auth list
Path           Type          Accessor                    Description                 Version
----           ----          --------                    -----------                 -------
devops/        approle       auth_approle_c0473ce8       DevOps Admin credentials    n/a
kubernetes/    kubernetes    auth_kubernetes_c7bf907f    n/a                         n/a
token/         token         auth_token_751e8ae6         token based credentials     n/a
```

Then I'll create 'readonly' policy for kubernetes:
```text
$ cat /etc/vault.d/policy2.hcl
path "devops/data/project1/secret1" {
  capabilities = ["read"]
}
$ vault policy list
default
devopsadmin
root
$
$ vault policy write kubepolicy /etc/vault.d/policy2.hcl
Success! Uploaded policy: kubepolicy
$
$ vault policy read kubepolicy
path "devops/data/project1/secret1" {
  capabilities = ["read"]
}
```

Next I'll create role 'kubereadonlyrole' for SA 'mypythonappsa' for every namespace so I can change my deployment later and with deafult four days TTL for Tokens and Max TTL for for 6 days which some extra days for which Token can be extended:
```text
$ vault write auth/kubernetes/role/kubereadonlyrole bound_service_account_names=mypythonappsa bound_service_account_namespaces='*' policies=kubepolicy ttl=96h token_max_ttl=144h
Success! Data written to: auth/kubernetes/role/kubereadonlyrole
$
$ vault list auth/kubernetes/role
Keys
----
kubereadonlyrole
$
$ vault read auth/kubernetes/role/kubereadonlyrole
Key                                 Value
---                                 -----
alias_name_source                   serviceaccount_uid
bound_service_account_names         [mypythonappsa]
bound_service_account_namespaces    [*]
policies                            [kubepolicy]
token_bound_cidrs                   []
token_explicit_max_ttl              0s
token_max_ttl                       144h
token_no_default_policy             false
token_num_uses                      0
token_period                        0s
token_policies                      [kubepolicy]
token_ttl                           96h
token_type                          default
ttl                                 96h
```

Next I'll have to jump to `Kubernetes configuration for Vault` section for JWT Token creation before I can finish Vault kubereadonlyrole auth config here. 


Now I got required values and I can continue Kubenetes auth config, disable_iss_validation="true" is recommended value:
```text
$ JWT=$(cat /opt/vault/tls/JWT.crt)
$ KUBE_CA_CERT=$(cat /opt/vault/tls/KUBE_CA_CERT.crt)
$
$ vault write auth/kubernetes/config kubernetes_host="https://kube1:6443" token_reviewer_jwt="$JWT" kubernetes_ca_cert="$KUBE_CA_CERT" disable_local_ca_jwt="true" issuer="kubernetes/serviceaccount" disable_iss_validation="true"
Success! Data written to: auth/kubernetes/config
$
$ vault read auth/kubernetes/config
Key                       Value
---                       -----
disable_iss_validation    false
disable_local_ca_jwt      true
issuer                    kubernetes/serviceaccount
kubernetes_ca_cert        -----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIIdyuuIfzVXj0wDQYJKoZIhvcNAQELBQAwFTETMBEGA1UE
AxMKa3ViZXJuZXRlczAeFw0yMzEyMTgxNDU5MTFaFw0zMzEyMTUxNTA0MTFaMBUx
EzARBgNVBAMTCmt1YmVybmV0ZXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC7xwM5b76DxzkRvdi69NaJEbbORQrb6xiMLw1VQJNDr6VJwQH5VoGr+ZPk
0YmhCt7OsYpYX5nINnntXLuCyjFucfIl0oUNsYnfxY2aMVwcIs9EkB95mDghGZn5
C4TA6H773nZsV1IPv/rgW6H10Y7kp46roQludng6zEmxObAwRw4XrecVTsVTAsyR
Hk9X2uk9Acz8N1mhucJpfh7mmeNEPtZkY3scEGMDTw2+mD2gVUWWt7pz6z3G+za6
V5gBconeRJr6GglnIrGyw/hIdExVSWiRplZ3cxBbxfkGGWfNv/VII5jVWTdJdrX/
y1/rDQFj4N1jMz1KtZ0oCrpF1BA9AgMBAAGjWTBXMA4GA1UdDwEB/wQEAwICpDAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTCCX7HDc26tDiofjH56eTAwDQJ/zAV
BgNVHREEDjAMggprdWJlcm5ldGVzMA0GCSqGSIb3DQEBCwUAA4IBAQBlePNQ6zYQ
udKuRBF/hcJ/AK/vqsagQJ5ABBTxZQ3XMV36OfxQAz0eUlbDb3u948uhWcryfmQ/
cA0KVIAXE7OR9U+XKklunu1qIutNEiOlNYtsoAp126cUO3/paVp0/Bw9HTi50D/R
3TRFxcK1BJeyFMfhgx9hxBbyfDoiGMddSgIFqY+IeBNh807o/dhs/trvEcOxmnr7
SgelYIhm6uQkeeu+c9WQWoTZ7NqCLX6a7yiXp2QQ2+OI4xh6VGIRi1RIr8URvqca
vUW365wH4L4GO4HTUmnbTCIA4MmoZEPz/zL/kK6QMzt2vCyWOWvIVGhPfg7uQIw/
032S0xT8hprg
-----END CERTIFICATE-----
kubernetes_host           https://kube1:6443
pem_keys                  []
```

Test login from K8s cmd line, first I set JWT. From Vault this auth method access K8s TokenReview API to validate JWT, so serviceaccount need to have access to to TokenReview API and I need RBAC config to do so:
```text
$ K8s control-plane:
$ JWT=$(kubectl get secret vault-auth-secret -n test2 --output 'go-template={{ .data.token }}' | base64 --decode)
$
$ From remote Ansible IaC host:
$ ansible-playbook main.yml --tags "kubernetes-rbac"
$
$ Back in K8s control-plane:
$ curl -k --request POST --data '{"jwt": "'$JWT'", "role": "kubereadonlyrole"}' https://192.168.122.14:8200/v1/auth/kubernetes/login | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1725  100   778  100   947  20807  25327 --:--:-- --:--:-- --:--:-- 46621
{
  "request_id": "81023049-c232-9f8c-5b39-a66786dabfb5",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": null,
  "wrap_info": null,
  "warnings": null,
  "auth": {
    "client_token": "hvs.CAES...",
    "accessor": "Wmy4U5PnTAFjRBljFKr3FhCX",
    "policies": [
      "default",
      "kubepolicy"
    ],
    "token_policies": [
      "default",
      "kubepolicy"
    ],
    "metadata": {
      "role": "kubereadonlyrole",
      "service_account_name": "mypythonappsa",
      "service_account_namespace": "test2",
      "service_account_secret_name": "vault-auth-secret",
      "service_account_uid": "22d14045-e5be-4a9a-b626-fbb5b791671f"
    },
    "lease_duration": 345600,
    "renewable": true,
    "entity_id": "e1604b67-066d-d98c-57b8-fc95b87db58a",
    "token_type": "service",
    "orphan": true,
    "mfa_requirement": null,
    "num_uses": 0
  }
}
```

Next test is read, in this case I can get Vault to tell us curl string:
```text
$ vault kv get -output-curl-string -mount=devops/data -version=4 project1/secret1
curl -H "X-Vault-Request: true" -H "X-Vault-Token: $(vault print token)" http://127.0.0.1:8200/v1/devops/data/project1/secret1?version=4
```

Read test from remote with above curl, token is one that previous login gave hvs.CAES...:
```text
$ curl -k -H "X-Vault-Request: true" -H "X-Vault-Token: hvs.CAES..." https://192.168.122.14:8200/v1/devops/data/project1/secret1?version=4 | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   335  100   335    0     0  21916      0 --:--:-- --:--:-- --:--:-- 22333
{
  "request_id": "e50b2b0a-b9c5-65c3-796f-7c6a6fb03478",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "data": {
      "password": "bar",
      "username": "foo"
    },
    "metadata": {
      "created_time": "2024-02-09T13:19:59.627850779Z",
      "custom_metadata": null,
      "deletion_time": "",
      "destroyed": false,
      "version": 4
    }
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```


Pod iss has different issuer value, so for Pod connections I need:
```text
$ vault write auth/kubernetes/config kubernetes_host="https://kube1:6443" token_reviewer_jwt="$JWT" kubernetes_ca_cert="$KUBE_CA_CERT" disable_local_ca_jwt="true" issuer="https://kubernetes.default.svc.cluster.local" disable_iss_validation="true"
Success! Data written to: auth/kubernetes/config
$
$ vault read auth/kubernetes/config
Key                       Value
---                       -----
disable_iss_validation    true
disable_local_ca_jwt      true
issuer                    https://kubernetes.default.svc.cluster.local
```

Now I can continue with patching Pod for activating Vault. 


### Kubernetes configuration for Vault


#### Sidecar agent deployment

I set spesific tags for Sidecar deployment in WSL2Fun main.yml Ansible variables for deployment role helm-sidecaragent only for personal interest with versions, I also set loglevel to debug:
```text
VAULT_K8S_TAG: "1.3.1"
VAULT_TAG: "1.d15.2"
LOG_LEVEL: "debug"
$
$ ansible-playbook main.yml --tags "helm-sidecaragent"
ok: [kube1] =>
  msg:
  - mypythonapp-85b9fd95f5-6jjvg
  - vault-k8s-agent-injector-5b898c6cc6-dbn4m
$ k get pods -n test2
NAME                                        READY   STATUS    RESTARTS       AGE
mypythonapp-85b9fd95f5-6jjvg                1/1     Running   1 (128m ago)   22h
vault-k8s-agent-injector-5b898c6cc6-dbn4m   1/1     Running   0              55m
```


#### Serviceaccount

Service accounts are intended to provide identity for Pod, changes into SA require Pod restart.  

I created 'mypythonappsa' SA for Pod. In Helm chart I set `automountServiceAccountToken: false`, because I wan't to create long lived SA Token which I use in Vault auth:
```text
$ ansible-playbook main.yml --tags "kubernetes-sa"
$
$ k get sa -n test2
NAME                       SECRETS   AGE
default                    0         45h
mypythonappsa              0         22h
```

If I set 'automountServiceAccountToken: true' in Ansible, I get SA Token automatically mounted into Pod:
```text
$ k get pod mypythonapp-85994db9f5-cspr4 -n test2 -o yaml
   volumeMounts:
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access-4hxh4
      readOnly: true

 serviceAccount: mypythonappsa
 serviceAccountName: mypythonappsa

 volumes:
  - name: kube-api-access-4hxh4
    projected:
      defaultMode: 420
      sources:
      - serviceAccountToken:
          expirationSeconds: 3607
          path: token
      - configMap:
          items:
          - key: ca.crt
            path: ca.crt
          name: kube-root-ca.crt
$
k exec -it mypythonapp-85994db9f5-cspr4 -n test2 -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
eyJhbGciOiJSUzI1NiIsImtpZCI6IlVabGZB
```


#### Values for Vault kube auth config 1: kubernetes_host 

I have set /etc/hosts in Vault and verify it with ping:
```text
$ kubectl config view --raw --minify --flatten --output 'jsonpath={.clusters[].cluster.server}{"\n"}'
https://kube1:6443
Test with ping from Vault:
$ ping kube1
PING kube1 (192.168.122.10) 56(84) bytes of data.
64 bytes from kube1 (192.168.122.10): icmp_seq=1 ttl=64 time=1.21 ms
64 bytes from kube1 (192.168.122.10): icmp_seq=2 ttl=64 time=0.476 ms
```


#### Values for Vault kube auth config 2: JWT Token

Here is 'long lived SA Token' which I'll set in legacy way to have non expiring Token. K8s favor Time Bound Tokens for security reasons, so in the near future I'll probably has to change this:
```text
$ ansible-playbook main.yml --tags "kubernetes-secret"
ok: [kube1] =>
  msg:
    changed: false
    failed: false
    method: update
    result:
      apiVersion: v1
      data:
        ca.crt: LS0tLS...
$
$  k get secrets -n test2
NAME                              TYPE                                  DATA   AGE
sh.helm.release.v1.vault-k8s.v1   helm.sh/release.v1                    1      43m
vault-auth-secret                 kubernetes.io/service-account-token   3      14m
$
k describe secret vault-auth-secret -n test2
Name:         vault-auth-secret
Namespace:    test2
Labels:       <none>
Annotations:  kubernetes.io/service-account.name: mypythonappsa
              kubernetes.io/service-account.uid: 00f15b91-d5f4-40fa-9ab1-ddefe2bf510b

Type:  kubernetes.io/service-account-token

Data
====
ca.crt:     1107 bytes
namespace:  5 bytes
token:      eyJhbGciOiJSUz...
$
k8s-admin@kube1:~$ kubectl get secret vault-auth-secret -n test2  --output 'go-template={{ .data.token }}' | base64 --decode > JWT.crt
$
$ Below I copy above value from remote to remote:
$ scp -3 -p k8s-admin@192.168.122.10:~/Hashi/JWT.crt management@192.168.122.14:~/JWT.crt
$
# mv JWT.crt /opt/vault/tls/
#
# chown vault:vault /opt/vault/tls/JWT.crt
#
# chmod 600 /opt/vault/tls/JWT.crt
$
$ ls -la /opt/vault/tls/JWT.crt
-rw------- 1 vault vault 908 Feb  9 13:43 /opt/vault/tls/JWT.crt
```

Kube API will automatically populate correct values for above secret because annotation and type parameters. 

JWT Token issuer 'iss':
```text
$ cat /opt/vault/tls/JWT.crt | jq -R 'split(".") | .[1] | @base64d | fromjson'
{
  "iss": "kubernetes/serviceaccount",
  "kubernetes.io/serviceaccount/namespace": "test2",
  "kubernetes.io/serviceaccount/secret.name": "vault-auth-secret",
  "kubernetes.io/serviceaccount/service-account.name": "mypythonappsa",
  "kubernetes.io/serviceaccount/service-account.uid": "22d14045-e5be-4a9a-b626-fbb5b791671f",
  "sub": "system:serviceaccount:test2:mypythonappsa"
}
```

Notice the difference between JWT and KUBE_CA_CERT issuer, this is important difference between cmd line curl and Pod Agent Injector access!


#### Values for Vault kube auth config 3: KUBE_CA_CERT

I'll read KUBE_CA_CERT from K8s and write result to vault host:
```text
$ ssh k8s-admin@192.168.122.10 kubectl config view --raw --minify --flatten --output 'jsonpath={.clusters[].cluster.certificate-authority-data}' | base64 --decode | ssh -T management@192.168.122.14 "cat > /home/management/KUBE_CA_CERT.crt"
$
# mv KUBE_CA_CERT.crt /opt/vault/tls/
# chown vault:vault /opt/vault/KUBE_CA_CERT.crt
#
# chmod 600 /opt/vault/tls/KUBE_CA_CERT.crt
$
$ ls -la /opt/vault/tls/KUBE_CA_CERT.crt
-rw------- 1 vault vault 1107 Feb  9 13:30 /opt/vault/tls/KUBE_CA_CERT.crt
```

Cert issuer 'iss':
```text
$  echo '{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest"}' \
>   | kubectl create -f- --raw /api/v1/namespaces/default/serviceaccounts/default/token \
>   | jq -r '.status.token' \
>   | cut -d . -f2 \
>   | base64 -d
{"aud":["https://kubernetes.default.svc.cluster.local"],"exp":1707484026,"iat":1707480426,"iss":"https://kubernetes.default.svc.cluster.local","kubernetes.io":{"namespace":"default","serviceaccount":{"name":"default","uid":"509c4114-800e-4000-9bff-d32040219910"}},"nbf":1707480426,"sub":"system:serviceaccount:default:default"}
```

#### Patching Pod

Patch will only change annotation which activate Sidecar Agent:
```text
$ k annotate --overwrite pods mypythonapp-7d46c57c86-b5n4n vault.hashicorp.com/agent-inject=true -n test2
pod/mypythonapp-7d46c57c86-b5n4n annotated
$
```


### Helm chart modification for Vault Agent

Vault Agent Injector modifies App with Kubernetes annotations, in my Lab I'll set vault.hashicorp.com/agent-inject: false and use online patch to change that value and also get mount into /vault/secrets/data.json to replace hard coded data.json. To add needed annotations I'll create chart version 0.0.3 for app version 0.0.2:
```text
$ helm repo update
Hang tight while we grab the latest from your chart repositories...
...Successfully got an update from the "hashicorp" chart repository
...Successfully got an update from the "custom-repo" chart repository
...Successfully got an update from the "bitnami" chart repository
Update Complete. ⎈Happy Helming!⎈
$
$ helm search repo custom-repo -l
NAME                    CHART VERSION   APP VERSION     DESCRIPTION
custom-repo/busybox     0.0.1           latest          A Helm chart for Kubernetes
custom-repo/mypythonapp 0.0.3           0.0.2           A Helm chart for Kubernetes
custom-repo/mypythonapp 0.0.2           0.0.2           A Helm chart for Kubernetes
custom-repo/mypythonapp 0.0.1           0.0.1           A Helm chart for Kubernetes
```

Next I'll change required chart version in Ansible role 'helm'mypythonapp' and re-deploy:
```text
~/WSL2Fun$ ansible-playbook main.yml --tags "helm-mypythonapp"
$
~$ helm list -n test2
NAME            NAMESPACE       REVISION        UPDATED                                 STATUS          CHART                   APP VERSION
mypythonapp     test2           2               2024-02-08 15:12:20.41782401 +0200 EET  deployed        mypythonapp-0.0.3       0.0.2
vault-k8s       test2           1               2024-02-07 13:46:44.974861276 +0200 EET deployed        vault-0.27.0            1.15.2
```

Now Pod has new annotations for Vault, agent-inject is false because I will change that with patch later on: 
```text
$ k describe pod mypythonapp-85994db9f5-cspr4 -n test2
Annotations:      
                  vault.hashicorp.com/agent-inject: false
                  vault.hashicorp.com/agent-inject-secret-conf.json: devops/data/project1/secret1
                  vault.hashicorp.com/role: kubereadonlyrole
```


## Vault Audit Log

```text
# touch /var/log/vault-audit.log
# chown vault:vault /var/log/vault-audit.log
# chmod 600 /var/log/vault-audit.log
# ls -la /var/log/vault-audit.log
-rw------- 1 vault vault 0 Feb  9 17:16 /var/log/vault-audit.log
$
$ vault audit enable file file_path=/var/log/vault-audit.log
Success! Enabled the file audit device at: file/
$
$ tail -f /var/log/vault-audit.log | jq
{
  "time": "2024-02-09T15:20:30.176538674Z",
  "type": "response",
  "auth": {
    "policy_results": {
      "allowed": true
    },
    "token_type": "default"
  },
  "request": {
    "id": "9a47fcdb-eb9b-bb19-6996-091a9ce4946f",
    "operation": "update",
```


## My Python App


### Docker Build

Build `docker build -t jrcjoro1/mypythonapp:0.0.1 .`

Push: `docker push jrcjoro1/mypythonapp:0.0.1`


### Create Helm chart

Create base chart: `helm create mypythonapp`

Small values.yaml editions: `repository: jrcjoro1/my-python-app`, `tag: 0.0.1` and `port: 8080`

check Helm `helm lint mypythonapp/`


### Container secrets path modification for Vault

In mypythonapp version 0.0.1 I had data.json located in same folder with python code. Vault read secrets from path /vault/secrets, so I'll have to change Python code to read from correct path and Dockerfile to add data.json into correct location, so I'll create app and chart version 0.0.2.

Similar way I'll change Helm chart to include tag: 0.0.2 and update github helm-repo with new Chart version 0.0.2:
```text
$ helm search repo custom-repo -l
NAME                    CHART VERSION   APP VERSION     DESCRIPTION
custom-repo/busybox     0.0.1           latest          A Helm chart for Kubernetes
custom-repo/mypythonapp 0.0.2           0.0.2           A Helm chart for Kubernetes
custom-repo/mypythonapp 0.0.1           0.0.1           A Helm chart for Kubernetes
```


### Add Custom mypythonapp Chart to github

In my previous lab I already created custom github Helm repo for Busybox chart, now I have add mypythonapp chart to that repo:
```text
$ helm package Charts/mypythonapp
Successfully packaged chart and saved it to: ~/helm-repo/mypythonapp-0.0.1.tg
$ 
$ mv mypythonapp-0.0.1.tgz Packages/
$
$ helm repo index --url Packages/mypythonapp-0.0.1.tgz --merge index.yaml . 
```

Helm index doesn't make urls path correctly, so small edition is needed for index.yaml before updating git repo:
```text
$ git add .
$
$ git commit -m "mypythonapp"
$
$ git push
```

Test Custom repo in Kubernetes with Helm:
```text
k8s-admin@kube1:~$ helm repo list
NAME            URL
bitnami         https://charts.bitnami.com/bitnami
custom-repo     https://jouros.github.io/helm-repo
k8s-admin@kube1:~$ helm repo update
Hang tight while we grab the latest from your chart repositories...
...Successfully got an update from the "custom-repo" chart repository
...Successfully got an update from the "bitnami" chart repository
Update Complete. ⎈Happy Helming!⎈
k8s-admin@kube1:~$ helm search repo custom-repo -l
NAME                    CHART VERSION   APP VERSION     DESCRIPTION
custom-repo/busybox     0.0.1           latest          A Helm chart for Kubernetes
custom-repo/mypythonapp 0.0.1           0.0.1           A Helm chart for Kubernetes
```

I prefer Ansible in deployments, so lets deploy my-python-app, role 'helm-mypythonapp' can be found from my WSL2Fun Ansible roles:
```text
$ ansible-playbook main.yml --tags "helm-mypythonapp"
ok: [kube1] =>
  msg: |-
    Release "mypythonapp" does not exist. Installing it now.
    NAME: mypythonapp
    LAST DEPLOYED: Tue Feb  6 14:53:24 2024
    NAMESPACE: test2
    STATUS: deployed
    REVISION: 1
    NOTES:
    1. Get the application URL by running these commands:
      export POD_NAME=$(kubectl get pods --namespace test2 -l "app.kubernetes.io/name=mypythonapp,app.kubernetes.io/instance=mypythonapp" -o jsonpath="{.items[0].metadata.name}")
      export CONTAINER_PORT=$(kubectl get pod --namespace test2 $POD_NAME -o jsonpath="{.spec.containers[0].ports[0].containerPort}")
      echo "Visit http://127.0.0.1:8080 to use your application"
      kubectl --namespace test2 port-forward $POD_NAME 8080:$CONTAINER_PORT
```

Check from Kube:
```text
$ k get pods -n test2
NAME                          READY   STATUS    RESTARTS   AGE
mypythonapp-ff9f6d8db-vprt2   1/1     Running   0          11s
$
$ k get svc -n test2
NAME          TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
mypythonapp   ClusterIP   10.107.202.74   <none>        8080/TCP   23s
$
$ curl http://10.107.202.74:8080
{"data": {"username": "correct_user", "password": "correct_password"}}
```

