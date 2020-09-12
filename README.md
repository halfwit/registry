# registry
Inferno's registry, done in a more plan9-like manner

```
# Copy into /sys/src/cmd/ndb 
mk all && mk install
```

## Bugs/Gotchas
The registry must be in the same namespace as cs to be able to translate addresses, be sure to set up your namespaces accordingly!

## Future
There is work towards having ndb/registry act in resolver mode, but it hasn't been completely ironed out.
The basic gist would be, you run a main registry for your entire network, and add an entry into your ipnet tuple for `registry=thatip`
Then you start the rest of your ndb/registry sessions with -s, which uses the main to resolve any query; but also allows resolution from any other arbitrary registry server you add to your ndb.
