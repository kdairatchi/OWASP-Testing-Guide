# OWASP Cryptography Testing Resources  

Reference: OWASP Testing Guide v4.2  

## Official Tools  

### SSL/TLS Testing  
- [SSLyze](https://github.com/nabla-c0d3/sslyze)  
- [TestSSL.sh](https://testssl.sh/)  
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)  
- [OpenSSL](https://www.openssl.org/)  

### Cryptographic Analysis  
- [CrypTool](https://www.cryptool.org/)  
- [HashCat](https://hashcat.net/)  
- [John the Ripper](https://www.openwall.com/john/)  
- [Cryptographic Attack Tools](https://github.com/CrypTools)  

### Padding Oracle Testing  
- [PadBuster](https://github.com/GDSSecurity/PadBuster)  
- [Padding Oracle Attacker](https://github.com/KishanBagaria/padding-oracle-attacker)  
- [POET - Padding Oracle Exploitation Tool](https://github.com/liamg/poet)  

### Network Traffic Analysis  
- [Wireshark](https://www.wireshark.org/)  
- [tcpdump](https://www.tcpdump.org/)  
- [Burp Suite](https://portswigger.net/burp)  
- [OWASP ZAP](https://www.zaproxy.org/)  

## Official Documentation  
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)  
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)  
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)  

## Best Practices  

### SSL/TLS Configuration  
1. Protocol Versions  
   - Disable SSL 2.0, 3.0  
   - Enable TLS 1.2, 1.3  
   - Disable older TLS versions  

2. Cipher Suites  
   - Use strong cipher suites  
   - Disable weak ciphers  
   - Implement proper cipher order  

### Cryptographic Implementation  
1. Algorithm Selection  
   - Use standard algorithms  
   - Avoid custom implementations  
   - Follow NIST recommendations  

2. Key Management  
   - Proper key generation  
   - Secure key storage  
   - Regular key rotation  
   - Key backup procedures  

### Common Testing Scenarios  
1. Transport Layer Security  
   - Certificate validation  
   - Protocol verification  
   - Cipher suite testing  
   - Perfect forward secrecy  

2. Data Protection  
   - Encryption at rest  
   - Encryption in transit  
   - Key storage security  
   - Random number generation  

3. Common Vulnerabilities  
   - Weak algorithms  
   - Poor key management  
   - Insufficient entropy  
   - Padding oracle attacks