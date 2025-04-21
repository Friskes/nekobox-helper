## vpn-configurator

### A CLI for creating a configuration file for Amnezia, WireSock, WireGuard, and other clients with separate address tunneling. As well as a CLI for converting files with IP addresses to various formats.

---

#### CLI Features

- 1. Converting a file with ip addresses from the `amnezia` format to the `plaintext` format and vice versa.

- 2. Combine files in the same format with ip addresses into a single file.

- 3. Creating a `Amnezia`, `WireSock`, `WireGuard` and other configuration file for separate tunneling for `WireGuard` protocol.
Tunneling options:
  - 3.1. Proxying the specified ip addresses.
  - 3.2. Proxying all ip addresses.

- 4. Creating a `nekobox` android configuration file for separate tunneling for `vless` protocol.
Tunneling options:
  - 4.1. Proxy only ip addresses from the file with ip addresses, all other traffic is bypassed.
  - 4.2. Proxy all traffic, only ip addresses from the file with ip addresses are bypassed.

---

> You can use my personal collections of files with the ip addresses that I have attached to the repository (`youtube`, `chatgpt`, `jetbrains` services) in folder `ips` or you can collect the ip addresses you need yourself using the links below.
- [various collections of ip addresses](https://gist.github.com/iamwildtuna/7772b7c84a11bf6e1385f23096a73a15)
- [amnezia format ip addresses](https://gist.github.com/iamwildtuna/ea245d39c60753db9150e5fb0da4a5b7)
- [website with ip addresses 1](https://rockblack.su/vpn/dopolnitelno/diapazon-ip-adresov)
- [website with ip addresses 2](https://rockblack.pro/vpn/dopolnitelno/diapazon-ip-adresov)
- [website with ip addresses 3](https://iplist.opencck.org)
- [discord ip addresses](https://github.com/GhostRooter0953/discord-voice-ips)

---

#### Launch
To run the program on Windows, you can use the file: `vpn_configurator_vX.X.X.exe`
To run the program on MacOS, you can use the file: `vpn_configurator_vX.X.X`

If you have a python interpreter on your system, you can use the file to run program: `vpn_configurator.py`

---

#### Import in the amnezia desktop/android app
To import the generated configuration file:
- 1. Click on the `+` icon in main page
- 2. Select option `The connection settings file`
- 3. Select your configuration file
- 4. If the application suggests enabling obfuscation, I recommend enabling it
- 5. Click `Connect` button
- The profile is ready to use!

---

#### Import in the nekobox android app
To import the generated configuration file:
- 1. Go to the `Configuration page` in the nekobox app
- 2. Click on the `file+` icon
- 3. Click `Import from file`
- 4. Select the generated file on your device.
- The profile is ready to use!
