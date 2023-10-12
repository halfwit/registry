# Registry

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

This is used by ndb/registry to find your network svcfs

Add the following to your /cfg/$sysname/cpurc, where $sysname matches what you entered above.

```
# Assuming you add a "registry" port mapping
aux/svcfs -m /mnt/services /adm/services
aux/listen1 -t tcp!*!registry /bin/exportfs -r /mnt/services
```
## Pieces

Below are the main parts. Basic setup only requires an ndb/registry instance and ndb/regquery

### aux/svcfs

Usage: `aux/svcfs [-r] [-m mtpt] servicesfile`

`svcfs` will periodically check a service is still alive with a gradual backoff, capping off at hourly.
`svcfs` manages the contents of a file, `/adm/services`, which it will read in on startup
It serves up on `/mnt/services`, making a new directory creates a new service,
The dir contains many of the following files: 
 - addr
 - status (ok/down)
 - uptime
 - description
 - fd0/fd1 (?)

Services may be read by anyone, but can only be modified by the creator or registry owner. Request must come from users in the same authdom.

### ndb/registry 

Usage: `ndb/registry [-r] [-s srvname]`
- `-r` do not parse /cfg/$sysname/registry
- `-s` Alternate address for Registry server

Registry connects to a `svcfs`, by default checking for an entry in your local ipnet=. 
It parses `/cfg/$sysname/registry`, an ndb-formatted list of local services. 

```
## /cfg/mysystem/registry

# Local-only service, this is not written to the svcfs
service=myservice
    addr=tcp!myserver!19293
    description='My local-only service'
    local=true

# Network-shared service, this is written to the svcfs
service=mysharedservice
    addr=tcp!myserver!19294
    description='My shared service'
```

In addition to the above style of service tuples, we could also handle local pseudo-services:

```
service='!g'
    addr=local!/bin/gcli
    description='Search Google from the command line'
    local=true

service=plumber
    addr=local!/srv/plumb
    description='Local plumber instance'
    local=true
```

The point of which is more for bookkeeping, populating menus in an automated way, etc

### ndb/regquery 
Usage: `nbd/regquery [-m mtpt] [-a] [query]`

Connects to `mtpt`, by default at `/mnt/registry` and issues a search for the given query. If no value is passed in, all entries will be returned.

- `-a` returns all services that match query, regardless of whether they are live or not

Searches are for partial matches, searching for `"speaker"` will return `"outside-speaker-front"` and `"living-room-speaker"`, for example.

### ndb/regdebug
Like regquery, but issues queries directly to the given svcfs

## Future
- The code!
- Libraries for services to publish services
- Integration into `cpurc`
