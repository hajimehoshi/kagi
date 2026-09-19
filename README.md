# Kagi

Kagi (鍵) is a simple password generator.

## Installing and Updating

Requires Go 1.26 or later.

```sh
go install github.com/hajimehoshi/kagi@latest
```

## Usage

Store the master password in the OS keychain:

```sh
kagi -set-master-password
```

The command prompts twice with terminal echo disabled. It stores the password
under service `kagi`, account `master`. Running it again replaces the password.

Generate passwords using the stored master password:

```sh
kagi SITES_FILE
```

Storage uses macOS Keychain, Windows Credential Manager, or Linux Secret Service
(which requires a running service and a session D-Bus). Keychain errors stop the
command; there is no file fallback.

To migrate from a master password file, enter the same password during setup.
Leading and trailing whitespace is trimmed, matching the previous file loader,
so the same master password and sites file produce the same generated passwords.
Verify the generated passwords before removing the old file. The master password
file argument is no longer supported.

## License

Kagi is licensed under Apache license version 2.0. See LICENSE file.
