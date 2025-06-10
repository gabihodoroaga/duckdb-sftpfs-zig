# sftpfs

Access remote files directly into duckdb instance using sftp.

Note: This is an experiment to see how hard will be to create a duckdb extension in zig. This is not production ready ... yet. Check todo section.

## Features

Read files from a remote server by providing all the information in the URI format `sftp://[username]:[password]@[host]:[port]/path/to/file`


```sql
SELECT * FROM read_csv_auto('sftp://testuser:testpass@localhost:2222/config/data/data_1.csv');
```

Configuration Options

Name	| Description | Type
-----|------|------
`sftp_identity_file` | Path to identity file, echivalent of the `-i` option | `VARCHAR`
`sftp_private_key` | The private key in PEM format | `VARCHAR`
`sftp_private_key_password` | The password required to decrypt the private key | `VARCHAR`
`sftp_username` | The user name | `VARCHAR`
`sftp_password` | The password | `VARCHAR`

Example

```sql
SET sftp_username = 'test';
SET sftp_password='abcd';
SELECT * FROM read_csv_auto('sftp://localhost:2222/config/data/data_1.csv');
```

## Building

Use version 1.3.0 of duckdb

```bash
cd duckdb
git fetch --all
git switch v1.3.0
```

Build duckdb

```bash
cd duckdb
make
```

```
zig build
```

## Use the extension

Run duckdb

```bash
./duckdb/build/release/duckdb -unsigned
```


Load the extension

```sql
FORCE INSTALL './zig-out/lib/sftpfs.duckdb_extension';
LOAD sftpfs;
```

Read data from a remote file

```sql
SELECT * FROM read_csv_auto('sftp://testuser:testpass@localhost:2222/config/data/data.csv');
```

## TODO:

- [ ] implement connection/session management
- [ ] improve caching (max size with lru, disable variable, reset)
- [ ] implement local file caching
- [ ] implement list remote files function
- [ ] implement globs
