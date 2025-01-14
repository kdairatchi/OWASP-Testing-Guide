# OWASP Client-side Testing Resources  

Reference: OWASP Testing Guide v4.2  

## Official Tools  

### DOM XSS Testing  
- [DOMXSSScanner](https://github.com/yaph/domxssscanner)  
- [XSS Hunter](https://xsshunter.com/)  
- [DOM Invader (Burp Extension)](https://portswigger.net/burp/documentation/desktop/tools/dom-invader)  
- [DOM Snitch](https://github.com/google/dom-snitch)  

### JavaScript Analysis  
- [JSHint](https://jshint.com/)  
- [ESLint](https://eslint.org/)  
- [RetireJS](https://retirejs.github.io/retire.js/)  
- [JSParser](https://github.com/nahamsec/JSParser)  

### Browser Developer Tools  
- [Chrome DevTools](https://developers.google.com/web/tools/chrome-devtools)  
- [Firefox Developer Tools](https://developer.mozilla.org/en-US/docs/Tools)  
- [Safari Web Inspector](https://developer.apple.com/safari/tools/)  
- [Microsoft Edge DevTools](https://docs.microsoft.com/en-us/microsoft-edge/devtools-guide-chromium/)  

### CORS Testing  
- [CORS Tester](https://github.com/RUB-NDS/CORStest)  
- [CORScanner](https://github.com/chenjj/CORScanner)  
- [Corsy](https://github.com/s0md3v/Corsy)  

### WebSocket Testing  
- [WebSocket King](https://websocketking.com/)  
- [Burp Suite WebSocket Testing](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets)  
- [OWASP ZAP WebSocket Add-on](https://www.zaproxy.org/docs/desktop/addons/websockets/)  

## Official Documentation  
- [OWASP DOM-based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)  
- [OWASP HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)  
- [OWASP CORS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html)  
- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)  

## Best Practices  

### Client-side Security Controls  
1. Input Validation  
   - Client-side validation  
   - Output encoding  
   - Content Security Policy  
   - Frame protection  

2. JavaScript Security  
   - Secure coding practices  
   - Library management  
   - Third-party script control  
   - Event handling  

3. Storage Security  
   - Local Storage  
   - Session Storage  
   - Cookies  
   - IndexedDB  

4. Communication Security  
   - CORS configuration  
   - WebSocket security  
   - Postmessage validation  
   - HTTPS usage  

### Testing Methodologies  
1. Static Analysis  
   - Code review  
   - Security headers  
   - JavaScript analysis  
   - CSS analysis  

2. Dynamic Analysis  
   - Runtime testing  
   - DOM manipulation  
   - Event triggering  
   - State management  

3. Security Headers  
   - Content Security Policy  
   - X-Frame-Options  
   - X-XSS-Protection  
   - HSTS