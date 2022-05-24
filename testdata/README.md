# Notes

Print keyset:

- java -jar p12dumper.jar changeit demokeys.cfg.p12
- java -jar p12dumper.jar changeit florence.cfg.p12
- java -jar p12dumper.jar changeit reader.cfg.p12

Each file is a p12 format that contains a key/value pair entry. The key is denoted by
the alias and the value is an arbitrary byte array whose meaning is user-specific.

For example, `demokeys.cfg.p12` has 4 entries:

`openssl pkcs12 -in demokeys.cfg.p12 -passin pass:changeit`
