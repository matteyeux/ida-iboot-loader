# IDA iBoot Loader

IDA loader for Apple's iBoot, SecureROM and AVPBooter. 

![Capture](https://user-images.githubusercontent.com/8758978/134245891-c458bcb1-632e-445b-9ace-2e8b798cba5e.PNG)


### Support

This loader supports IDA 7.5 to IDA 8.1 and works on all Apple ARM64 bootloaders even M1+.

### Installation

Copy `iboot-loader.py` to the loaders folder in IDA directory.

### Usage

Open a decrypted 64 bits iBoot image or a [SecureROM](https://securerom.fun) file with IDA. IDA should ask to open with this loader.

![Capture](https://user-images.githubusercontent.com/8758978/134242135-299bd5d0-cc62-44f0-8c8b-329361196942.PNG)

### Credits

* This code is based on argp's [iBoot64helper](https://github.com/argp/iBoot64helper)
* [iBoot-Binja-Loader](https://github.com/EliseZeroTwo/iBoot-Binja-Loader)
