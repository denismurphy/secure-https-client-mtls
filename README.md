# 🔒 Secure HTTPS Client with mTLS 🌐

HTTPS client implementation in C using mutual TLS (mTLS) authentication.

## 🔧 How It Works

1. 🌱 Initializes the TLS context and seeds the random number generator
2. 📜 Loads and parses certificates and private keys
3. 🔌 Sets up the network connection and configures SSL settings
4. 🤝 Performs the SSL/TLS handshake
5. 📤 Sends an HTTP GET request to the server
6. 📥 Receives and displays the server's response
7. 🧹 Cleans up and frees resources

## 🚦 Getting Started

To build and run this project:

1. Ensure you have CMake and a C compiler installed
2. Clone this repository
3. Navigate to the project directory
4. Install mbedTLS
5. Run the following commands:

```bash
mkdir build
cd build
cmake ..
make
./https-mtls
```

## 🔒 Security Note

This project demonstrates the use of mTLS for secure communication. In a real-world scenario, you should never hardcode certificates and private keys in your source code. Instead, use secure methods to store and retrieve these sensitive credentials.

## 📝 License

This project is licensed under the MIT License