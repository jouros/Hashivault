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

Start Vault: systemctl start vault

```text
# systemctl status vault --no-pager
● vault.service - "HashiCorp Vault - A tool for managing secrets"
     Loaded: loaded (/lib/systemd/system/vault.service; disabled; vendor preset: enabled)
     Active: active (running) since Mon 2024-01-29 17:15:06 EET; 3min 6s ago
       Docs: https://developer.hashicorp.com/vault/docs
   Main PID: 8681 (vault)
      Tasks: 7 (limit: 1101)
     Memory: 94.6M
        CPU: 139ms
     CGroup: /system.slice/vault.service
             └─8681 /usr/bin/vault server -config=/etc/vault.d/vault.hcl

Jan 29 17:15:06 hashivault vault[8681]:            Recovery Mode: false
Jan 29 17:15:06 hashivault vault[8681]:                  Storage: file
Jan 29 17:15:06 hashivault vault[8681]:                  Version: Vault v1.15.4, built 2023-12-04T17:45:28Z
Jan 29 17:15:06 hashivault vault[8681]:              Version Sha: 9b61934559ba31150860e618cf18e816cbddc630
Jan 29 17:15:06 hashivault vault[8681]: ==> Vault server started! Log data will stream in below:
Jan 29 17:15:06 hashivault vault[8681]: 2024-01-29T17:15:06.520+0200 [INFO]  proxy environment: http_proxy="" https_proxy="" no_proxy=""
Jan 29 17:15:06 hashivault vault[8681]: 2024-01-29T17:15:06.520+0200 [INFO]  incrementing seal generation: generation=1
Jan 29 17:15:06 hashivault vault[8681]: 2024-01-29T17:15:06.545+0200 [INFO]  core: Initializing version history cache for core
Jan 29 17:15:06 hashivault vault[8681]: 2024-01-29T17:15:06.545+0200 [INFO]  events: Starting event system
Jan 29 17:15:06 hashivault systemd[1]: Started "HashiCorp Vault - A tool for managing secrets".
#
#
#  netstat -anp -A inet | grep 8200
tcp        0      0 0.0.0.0:8200            0.0.0.0:*               LISTEN      8681/vault
```

Network test with curl:
```text
$ curl -k https://192.168.122.14:8200/v1/sys/seal-status
{"type":"shamir","initialized":false,"sealed":true,"t":0,"n":0,"progress":0,"nonce":"","version":"1.15.4","build_date":"2023-12-04T17:45:28Z","migration":false,"recovery_seal":false,"storage_type":"file"}
```

In my vault.hcl config I have both http and https listeners configured, http I'm going to user internally to localhost and https from outside:
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
