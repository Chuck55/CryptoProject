# CryptoProject
Crypto Project

Since our project uses java the commands for keygen, lock, and unlock must be
executed using the java command. For example:

java keygen -s <subject> -pub <public key file> -priv <private key file>

java lock -d <directory to lock/unlock> -p <action public key> -r <action private key> -s <the action subject>

java unlock -d <directory to lock/unlock> -p <action public key> -r <action private key> -s <the action subject>
