# android-fbe-decrypt

## Readme

Bruteforcing tool for guessing a device password given pwd credidential files and their AES
key from the keymaster database.

## Explanation

On older android versions, bruteforcing used to be relatively easy; you could get into the device
by removing locksettings.db, or some other files, which unfortunately no longer exist.

Since nougat, encryption has been possible. While on its own it just means we'd have to bruteforce
the password, and this was likely the case back in FDE days, modern hardware backed file based encryption 
required on every new android device is extremely complicated and to my knowledge impossible to simply 
bruteforce without extracting hardware keys that aren't on any regular phone partition.

This means your data is mostly secure even if your phone is stolen with an unlocked bootloader,
but it also means you can't get it back if you forget your password.

The android gatekeeper library talks to a hardware chip that enforces a timeout when an incorrect password
is picked too many times; which applies to the recovery partition as well, and TWRP
doesn't notify you of this. i found extracting the device keys to bruteforce them separately 
to be the next best bet.

My initial hope was that at some stage in the process, there is a file which can tell us 
if the provided user password is correct if we attempt decryption on it.

# Attempting bruteforce

The first step is to gain access to privileged parts of the filesystem, which means the device
bootloader has to be unlocked. Luckily, mtkclient let me use a hardware exploit to do exactly this
even though my bootloader was not unlocked previously.

[This article explains what I was trying to achieve here.](https://blog.quarkslab.com/android-data-encryption-in-depth.html)

```
pwd = generate new password
token = scrypt(pwd, R, N, P, Salt)
Application_id = token || Prehashed value
key = SHA512("application_id" || application_id)
AES_Decrypt(value_leaked_from_keymaster, key)

^ AES GCM decryption tells you if the password is wrong - it's possible to compare it separately
```

## Necessary files

- `/data/system_de/0/spblob/**` from android device - Synthetic password key
- `/data/misc/keystore/user_0/* (android <12), /data/misc/keystore/persistent.sqlite (android >= 12)` from android device - AES key for the password to be decrypted. You might need to extract it using SQLite. It's called synthetic_password_XXXXX
- openssl
- libscrypt

## ... And the problem

Keys stored on the filesystem in the keystore are encrypted using an AES key which is on a hardware chip, to my knowledge.
Regardless, source code for attempting to decrypt the spblob is there.

If you know how to proceed, please contact me as i still have a phone i need my data from. 
This repo is here for historical reasons and for anyone who is stupid enough to try this themselves.