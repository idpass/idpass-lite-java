# Notes

Print keyset:

- java -jar p12dumper.jar changeit demokeys.cfg.p12
- java -jar p12dumper.jar changeit florence.cfg.p12
- java -jar p12dumper.jar changeit reader.cfg.p12

Each file is a p12 format that contains a key/value pair. The key is denoted by
the alias and the value is an arbitrary byte array whose meaning is user-specific.
