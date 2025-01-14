# OWASP Business Logic Testing Resources  

Reference: OWASP Testing Guide v4.2  

## Official Tools  

### Web Application Testing  
- [Burp Suite](https://portswigger.net/burp)  
- [OWASP ZAP](https://www.zaproxy.org/)  
- [Postman](https://www.postman.com/)  
- [SoapUI](https://www.soapui.org/)  

### Request Forgery Testing  
- [CSRF Tester](https://owasp.org/www-project-csrftester/)  
- [XSRFProbe](https://github.com/0xInfection/XSRFProbe)  
- [RequestBin](https://requestbin.com/)  

### File Upload Testing  
- [FUZZ Database](https://github.com/fuzzdb-project/fuzzdb)  
- [SecLists](https://github.com/danielmiessler/SecLists)  
- [FileUploadScanner (Burp Extension)](https://github.com/modzero/mod0BurpUploadScanner)  

### Workflow Testing  
- [Selenium](https://www.selenium.dev/)  
- [Puppeteer](https://pptr.dev/)  
- [JMeter](https://jmeter.apache.org/)  
- [Process Flow Test Cases](https://github.com/OWASP/ASVS)  

## Official Documentation  
- [OWASP Business Logic Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html)  
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)  
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)  

## Best Practices  

### Business Logic Testing Strategies  
1. Process Flow Testing  
   - Identify critical workflows  
   - Map business processes  
   - Test sequence dependencies  
   - Verify state transitions  

2. Data Validation  
   - Business rule validation  
   - Data consistency checks  
   - Boundary value analysis  
   - Cross-field validations  

3. Access Control Testing  
   - Role-based access control  
   - Process-level permissions  
   - Workflow enforcement  
   - Time-based access  

4. Common Attack Scenarios  
   - Parameter manipulation  
   - Session state tampering  
   - Race conditions  
   - Logic bypasses  

### Security Controls  
1. Input Validation  
   - Business rule validation  
   - Data type checking  
   - Range checking  
   - Format validation  

2. Process Controls  
   - Workflow enforcement  
   - State management  
   - Transaction limits  
   - Rate limiting  

3. Output Validation  
   - Data consistency  
   - Business rule compliance  
   - Process completion verification  
   - Audit logging