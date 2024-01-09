Toptyp is an authenticator app for Windows. It will let you...

 - Set up two-factor authentication for your accounts by scanning QR codes.
 - Generate and copy QR codes quickly -- one mouse click or a few key presses.
 - Back up and restore your account secrets, either password-protected or not.
 - Print out your account information as QR codes.

[Download Version 1.0](https://github.com/PeterReid/toptyp/releases/tag/v1.0)

Toptyp does not sync or send your account information anywhere. Backups are in your hands, although it will remind you to make one after you make a change.

Toptyp is lightweight, starting nearly instantly and using less than 2MB of memory. To use most efficiently, open the program, type a few characters of the account you need into the already-focused search box, and press Enter to copy the code.


<img src="https://raw.githubusercontent.com/PeterReid/toptyp/master/usage.png"/>

### Building
Rust and Visual Studio 2022 are required to build this. After cloning the repository, navigate to `backend` and run `cargo build --release`. Then open toptyp.sln with Visual Studio and choose Build Solution.

### Why Toptyp
Toptyp was written to help prevent smartphones from being mandatory.
