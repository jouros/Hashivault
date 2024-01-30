# Hashivault

In this demo lab I will focus on Kubernetes integration for Hashicorp Vault, this is not production ready deployment e.g. secrets persistent storage is not configured. 

This demo is installed on WSL2

Ubuntu cloud init will deploy Hashi vault and 'vault' regular user account. For Ansible I have deployed 'management' user account with sudo, example below: 

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
```


## Configure Vault Policy


