# Services Registry

This is an interpretation of the Inferno Registry, for Plan9-like systems

## Configuration

Update your ipnet in /lib/ndb/local
```
ipnet=mynetwork ip=192.168.1.0 ipmask=255.255.255.0
    ipgw=192.168.1.1
    dns=1.1.1.1
    auth=authy
    registry=authy <---
    fs=servy
    cpu=crunchy
```

This is used by `net/services` and `net/svcquery` by default.

Add the following to your /cfg/$sysname/cpurc, where $sysname matches what you entered above.

```
# Assuming you add a "registry" port mapping
aux/svcfs -m /mnt/services /adm/services
aux/listen1 -t tcp!*!registry /bin/exportfs -r /mnt/services
```

## aux/svcfs

Usage: `aux/svcfs [-r] [-m mtpt] servicesfile`

- `-r` starts the server in readonly mode

`svcfs` will periodically check a service is still alive with a gradual backoff, capping off at hourly.

`svcfs` manages the contents of a file, `/adm/services`, which it will read in on startup
It serves up on mtpt, by default using `/mnt/services`

A service can be added by creating a directory. Services may be read by anyone, but can only be modified by the creator or registry owner. Write requests must come from users in the same authdom.

Each service dir contains many of the following files: 
 - address
 - authdom (Still a TODO)
 - status (ok/down)
 - uptime
 - description

### Notes
 - It may be beneficial to expose an events file that `services` can do a blocking read on, waiting for a service to be removed/added
 - `auth` is an optional address for the auth server to use

## svc/monitor 

Usage: `svc/services [-o]  [-s svcfs]`

- `-o` Alternate naming in services, `ipnet.sysname.svcname`
- `-s` Address of svcfs

monitor connects to a `svcfs`, by default checking for an entry in your local ipnet=. 
monitor will populate your local /srv with an fd pointing to all records in the given `svcfs`. 
- If the status of a service changes from Ok, it will be automatically removed
- multiple instances can be run, one per svcfs
- on exit, all mounted services should be kept alive; so on start it should handle silently failing when an entry already exists

## svc/query

Usage: `svc/query [-s svcfs] query`
- `-s` Address of svcfs. If none is given, it uses `registry=` from your ipnet

Query the svcfs for any services matching query. It returns a tuple for each match

```
$ svc/query speakers
service=speakers address=livingroom!12345 
    description='Living room speakers'
    uptime='4 days, 3 hour, 0 minutes'
    status=ok
service=speakers address=bedroom!1234
    description='Bedroom speakers'  
    uptime='55 days, 0 hours, 2 minutes'
    status=ok
```

## svc/publish 
Usage: `svc/publsh [-s svcfs] [-a authdom] svcname addr [attr value]`

Create a service entry on the given `svcfs`, by default using the `registry=` value in `/lib/ndb/local`. If a service already exists, it will attempt to update the svcfs with the attr/values given.

- `attr` can be one of `description` or `auth`

## svc/drop
Usage: `svc/drop [-s svcfs] [-a authdom] svcname`

This will remove the service entry from the `svcfs`. This must be ran as the user who created the service entry, or the hostowner of `svcfs`.

## Future
- Integration into `cpurc`
- Allow setting an Authdom for a services
