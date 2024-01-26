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

I'm are going to use selfsigned customer certificate, so /etc/vauld.d/vault.hcl need modification:
```text
 # HTTPS listener
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/opt/vault/tls/custom.crt"
  tls_key_file  = "/opt/vault/tls/custom.key"
}
```

