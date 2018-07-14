# RSA Project

## About the project

This program allows to encrypt messages using an RSA algorithm. It could be used for example to have an encrypted conversation over email. The sender would write a message in the app and send the encrypted message by email. The receiver would decrypt the encrypted message in the app using the same key to reveal the original message. (both absolutely need the same key in order to encode/decode the message).

## Dependencies

-2 people need to have a copy of this program and a copy of the same key file installed on their computers.
- JavaSDK 1.8
- JavaSE Runtime 1.8 (to try the compiled project)

## Getting Started

- Set a path to store the key file, named privateKey.dat (i.e. /Users/YOUR_NAME/Documents/privateKey.dat)

- If you already have a key installed, start writing your message and encrypt it. Otherwise generate a new key to share.

- Copy the encrypted message and paste in an email or something (also send the key file as attachment the first time)

- The other user will be able to decrypt your message by setting the path to the key file you sent.

- warning: of course, if anyone else has access to your key file, they will also be able to decrypt your messages!

## Screenshots

#### 3 users connecting
!["starting.png"](https://github.com/sylvain-gdk/chatty-app/blob/master/docs/starting.png)

#### Changing name
!["name-change.png"](https://github.com/sylvain-gdk/chatty-app/blob/master/docs/name-change.png)
