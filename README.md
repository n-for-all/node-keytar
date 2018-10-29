# keytar - Node module to manage system keychain

[![Travis Build Status](https://travis-ci.org/atom/node-keytar.svg?branch=master)](https://travis-ci.org/atom/node-keytar)
[![Windows Build Status](https://ci.appveyor.com/api/projects/status/github/atom/node-keytar?svg=true)](https://ci.appveyor.com/project/Atom/node-keytar)
[![Dependency Status](https://david-dm.org/atom/node-keytar.svg)](https://david-dm.org/atom/node-keytar)

A native Node module to get, add, replace, and delete passwords in system's keychain. On macOS the passwords are managed by the Keychain, on Linux they are managed by the Secret Service API/libsecret, and on Windows they are managed by Credential Vault.

## Installing

```sh
npm install keytar
```

### On Linux

Currently this library uses `libsecret` so you may need to install it before running `npm install`.

Depending on your distribution, you will need to run the following command:

* Debian/Ubuntu: `sudo apt-get install libsecret-1-dev`
* Red Hat-based: `sudo yum install libsecret-devel`
* Arch Linux: `sudo pacman -S libsecret`

## Building

  * Clone the repository
  * Run `npm install`
  * Run `npm test` to run the tests

## Docs

```javascript
const keytar = require('keytar')
```

Every function in keytar is asynchronous and returns a promise. The promise will be rejected with any error that occurs or will be resolved with the function's "yields" value.

### getPassword(server, account)

Get the stored password for the `server` and `account`.

`server` - The string server name.

`account` - The string account name.

Yields the string password or `null` if an entry for the given service and account was not found.

### setPassword(server, account, password)

Save the `password` for the `server` and `account` to the keychain. Adds a new entry if necessary, or updates an existing entry if one exists.

`server` - The string server name.

`account` - The string account name.

`password` - The string password.

Yields nothing.

### deletePassword(server, account)

Delete the stored password for the `server` and `account`.

`server` - The string server name.

`account` - The string account name.

Yields `true` if a password was deleted, or `false` if an entry with the given server and account was not found.

### findPassword(server)

Find a password for the `server` in the keychain.

`server` - The string server name.

Yields the string password, or `null` if an entry for the given server and account was not found.

### findCredentials(server)

Find all accounts for the `server` in the keychain.

`server` - The string server name.

Yields an array of `{ account: 'user', server: 'example.com', settings: {port, protocol?, domain?, path?} }`.
