# Week 1 Assignment

> Link to the sample document:
> 
> 
> [OWASP Top 10 Report.pdf](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/OWASP_Top_10_Report.pdf)
> 

# 📝 Assignment Overview

We are to study the OWASP Top 10 which is a regularly updated list of the most critical security risks facing web applications and make a comprehensive report on them including their descriptions and their business impact, and also illustrate an example by picking a CWE IDed vulnerability and demonstrating it on a real web application.

# 🐝 What is OWASP?

OWASP stands for the Open Web Application Security Project, a nonprofit organization focused on improving software security. The Top 10 list they issue provides guidance to developers, security professionals, and organizations about the most important vulnerabilities that need to be addressed in web applications.

# 🎯 OWASP 2021 Report’s Top 10

Although the list is updated periodically to reflect the ever evolving threat landscape, the last issued report for web applications was in 2021 and in that report, the vulnerabilties were: 

1. A01:2021-Broken Access Control
2. A02:2021-Cryptographic Failures
3. A03:2021-Injection
4. A04:2021-Insecure Design
5. A05:2021-Security Misconfiguration
6. A06:2021-Vulnerable and Outdated Components
7. A07:2021-Identification and Authentication Failures
8. A08:2021-Software and Data Integrity Failures
9. A09:2021-Security Logging and Monitoring Failures
10. A10:2021-Server-Side Request Forgery

# 📚 Vulnerability Documentation

## 1. Broken Access Control

Broken access control is a security vulnerability that occurs when a system's access control mechanisms, which are designed to restrict unauthorized users from accessing certain resources or performing specific actions, are not properly implemented or enforced. Access control is a fundamental aspect of information security and is crucial for protecting sensitive data and maintaining the integrity of systems.

### Impact:

When access control is broken, it can lead to unauthorized users gaining access to resources or performing actions they should not be allowed to. This can have serious consequences, such as data breaches, unauthorized modifications, data leaks, and more.

### List of Mapped CWEs:

| CWE Code | Name |
| --- | --- |
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') |
| CWE-23 | Relative Path Traversal |
| CWE-35 | Path Traversal: '.../...//' |
| CWE-59 | Improper Link Resolution Before File Access ('Link Following') |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor |
| CWE-201 | Exposure of Sensitive Information Through Sent Data |
| CWE-219 | Storage of File with Sensitive Data Under Web Root |
| CWE-264 | Permissions, Privileges, and Access Controls (should no longer be used) |
| CWE-275 | Permission Issues |
| CWE-276 | Incorrect Default Permissions |
| CWE-284 | Improper Access Control |
| CWE-285 | Improper Authorization |
| CWE-352 | Cross-Site Request Forgery (CSRF) |
| CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor |
| CWE-377 | Insecure Temporary File |
| CWE-402 | Transmission of Private Resources into a New Sphere ('Resource Leak') |
| CWE-425 | Direct Request ('Forced Browsing') |
| CWE-441 | Unintended Proxy or Intermediary ('Confused Deputy') |
| CWE-497 | Exposure of Sensitive System Information to an Unauthorized Control Sphere |
| CWE-538 | Insertion of Sensitive Information into Externally-Accessible File or Directory |
| CWE-540 | Inclusion of Sensitive Information in Source Code |
| CWE-548 | Exposure of Information Through Directory Listing |
| CWE-552 | Files or Directories Accessible to External Parties |
| CWE-566 | Authorization Bypass Through User-Controlled SQL Primary Key |
| CWE-601 | URL Redirection to Untrusted Site ('Open Redirect') |
| CWE-639 | Authorization Bypass Through User-Controlled Key |
| CWE-651 | Exposure of WSDL File Containing Sensitive Information |
| CWE-668 | Exposure of Resource to Wrong Sphere |
| CWE-706 | Use of Incorrectly-Resolved Name or Reference |
| CWE-862 | Missing Authorization |
| CWE-863 | Incorrect Authorization |
| CWE-913 | Improper Control of Dynamically-Managed Code Resources |
| CWE-922 | Insecure Storage of Sensitive Information |
| CWE-1275 | Sensitive Cookie with Improper SameSite Attribute |

### Example: CWE-201 (Exposure of Sensitive Information Through Sent Data)

Picked from the [MITRE Corporation’s](https://www.google.com/search?sca_esv=560657174&sxsrf=AB5stBjJ61beGCdl582XnoP-KG3uGwcTng:1693221582495&q=MITRE+Corporation&si=ACFMAn-RuLols7Cpmmm1c63YqwDqHg5PF1YUOfiWr1Cm6F7c5m2z62JPJrRz_D4vTN5PpInMrEjvCeRj6eHol9DoVpoY6a7pCxJRw2eysaNsxMhdWq9HEYxEQJ2JHfLRxX3xBo8vFqjKn8x4Sqgajzjd4y7tVqg-QLFkgy2LNxh5gK33qXN0hNQ%3D&sa=X&ved=2ahUKEwji_Mz3nf-AAxXd1AIHHZFQADUQ6RN6BAg-EAE&biw=1707&bih=942&dpr=1.5#ip=1) Web [Definitions for CWEs](https://cwe.mitre.org/data/definitions/201.html)

### **Description**

The code transmits data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor. Sensitive information could include data that is sensitive in and of itself (such as credentials or private messages), or otherwise useful in the further exploitation of the system (such as internal file system structure).

### **Business Impact**

Sending data that contains sensitive information to unauthorized actors can result in severe confidentiality breaches. This can lead to unauthorized access, data leaks, identity theft, and other malicious activities, undermining user trust, violating compliance regulations, and causing reputational damage. Additionally, the exploitation of system internals can provide attackers insights into the system's architecture, potentially aiding in further attacks and exploitation.

### Overview of the target:

The target website is [FastFoodHackings](https://bugbountytraining.com/fastfoodhackings/book.php). It is a website meant for bug bounty practice so I am authorized to hack into the website and/or to try to exploit common vulnerabilities.

### Methodology/Procedure to Exploit:

I found the above bug while monitoring the data exchange happening while I book an appointment in BurpSuite. I was exploring the website in a Chromium browser proxied thru BurpSuite. Even for anything that doesnt require proxying or intercepting, I usually browse the target here itself since it picks up HTTP and WebSocket history that I can later analyse, or it will pick up stuff on the dashboard (A feature I’m not too comfortable with).

The booking page normally works as follows:

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled.png)

The booking information is entered into the website

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%201.png)

The website returns an alert that its underprocess.

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%202.png)

And you are then redirected to a site that says that your order is pending confirmation.

So now I tried to intercept the traffic, This time I entered my own details and tried again (But not reccomended practice)

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%203.png)

And after the alert’s redirect, the packets intercepted were as follows: 

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%204.png)

The `order_id` parameter seemed interesting, since it had a garbled value after it being sent thru a HTTP GET request. So I tested this in the repeater. Since the value ended in an equals sign, this hints that it may be a `base64` encoding. So I decoded it returned the order id of `#42069` which was the order I got before. 

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%205.png)

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%206.png)

So I tested this to see if we can send the order IDs of people before me to be able to trick the website to show me their confirmation page.  I entered `42068`

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%207.png)

On rendering the response I got from sending `42068` in the repeater, I got the following order page: 

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%208.png)

Since we found access to another person’s order, it is considered to be broken access control and we have successfully exploited this website for the given CWE.

---

## 2. Cryptographic Failures

Cryptographic failures refer to vulnerabilities that arise from weak or improperly implemented cryptographic mechanisms. Cryptography is used to secure data transmission, authentication, and confidentiality. When cryptographic mechanisms are flawed, attackers can exploit these weaknesses to compromise sensitive information.

### Impact:

Cryptographic failures can result in the exposure of sensitive data, the compromise of communication channels, and the undermining of authentication and integrity. Attackers may be able to decrypt encrypted data, impersonate users, or execute man-in-the-middle attacks.

### List of Mapped CWEs:

| CWE Code | Vulnerability Name |
| --- | --- |
| CWE-261 | Weak Encoding for Password |
| CWE-296 | Improper Following of a Certificate's Chain of Trust |
| CWE-310 | Cryptographic Issues |
| CWE-319 | Cleartext Transmission of Sensitive Information |
| CWE-321 | Use of Hard-coded Cryptographic Key |
| CWE-322 | Key Exchange without Entity Authentication |
| CWE-323 | Reusing a Nonce, Key Pair in Encryption |
| CWE-324 | Use of a Key Past its Expiration Date |
| CWE-325 | Missing Required Cryptographic Step |
| CWE-326 | Inadequate Encryption Strength |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm |
| CWE-328 | Reversible One-Way Hash |
| CWE-329 | Not Using a Random IV with CBC Mode |
| CWE-330 | Use of Insufficiently Random Values |
| CWE-331 | Insufficient Entropy |
| CWE-335 | Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG) |
| CWE-336 | Same Seed in Pseudo-Random Number Generator (PRNG) |
| CWE-337 | Predictable Seed in Pseudo-Random Number Generator (PRNG) |
| CWE-338 | Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG) |
| CWE-340 | Generation of Predictable Numbers or Identifiers |
| CWE-347 | Improper Verification of Cryptographic Signature |
| CWE-523 | Unprotected Transport of Credentials |
| CWE-720 | OWASP Top Ten 2007 Category A9 - Insecure Communications |
| CWE-757 | Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade') |
| CWE-759 | Use of a One-Way Hash without a Salt |
| CWE-760 | Use of a One-Way Hash with a Predictable Salt |
| CWE-780 | Use of RSA Algorithm without OAEP |
| CWE-818 | Insufficient Transport Layer Protection |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort |

### Example: CWE-319 (Cleartext Transmission of Sensitive Information)

### **Description**

The product transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors. Many communication channels can be "sniffed" (monitored) by adversaries during data transmission. Adversaries might have privileged access to network interfaces or links, such as routers, enabling them to collect underlying data. This vulnerability can lead to security-critical data being exposed.

### **Business Impact**

Transmitting sensitive information in cleartext through communication channels that can be monitored by unauthorized actors can result in severe confidentiality breaches. Adversaries can gain access to the transmitted data, leading to unauthorized access, data leaks, identity theft, and other malicious activities. Additionally, when security-critical data is exposed, it can undermine user trust, violate compliance regulations, and cause reputational damage. The vulnerability significantly reduces the difficulty of exploitation for attackers, as they can easily intercept and misuse the transmitted sensitive information.

### Overview of the Target

I targetted the same website as before ([FastFoodHackings](https://bugbountytraining.com/fastfoodhackings/index.php)) and as iterated previously, I am authorized to exploit it for the vulnerability since it is meant for bug bounty practice.

### Methodology/Procedure to Exploit

This was a relatively simpler vulnerability to exploit. I just had to intercept the `HTTP` packets carrying the information while logging in. Since the website does not show `HTTPS` in the URL bar, I know that the data won’t be encrypted in transit.

And sure enough, once I used my name as username `owais` and the password as something like `mysecretpassword`, I was able to pick it up in the proxy in plain text.

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%209.png)

You can even pick this packet up over something like wireshark which only picks up packets and has no encryption decryption features whatsoever.

---

## 3. Injection

Injection vulnerabilities occur when untrusted input is improperly sanitized and then executed as part of a command or query. This allows attackers to manipulate the behavior of an application by injecting malicious code or commands into it. Common types of injection attacks include SQL injection and cross-site scripting (XSS).

### Impact:

Injection attacks can lead to unauthorized data access, data manipulation, and remote code execution. Attackers can steal sensitive information, modify or delete data, and compromise the security of an application and its users.

### List of Mapped CWEs:

| CWE Code | Vulnerability Name |
| --- | --- |
| CWE-20 | Improper Input Validation |
| CWE-74 | Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') |
| CWE-75 | Failure to Sanitize Special Elements into a Different Plane (Special Element Injection) |
| CWE-77 | Improper Neutralization of Special Elements used in a Command ('Command Injection') |
| CWE-78 | Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') |
| CWE-79 | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') |
| CWE-80 | Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) |
| CWE-83 | Improper Neutralization of Script in Attributes in a Web Page |
| CWE-87 | Improper Neutralization of Alternate XSS Syntax |
| CWE-88 | Improper Neutralization of Argument Delimiters in a Command ('Argument Injection') |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') |
| CWE-90 | Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection') |
| CWE-91 | XML Injection (aka Blind XPath Injection) |
| CWE-93 | Improper Neutralization of CRLF Sequences ('CRLF Injection') |
| CWE-94 | Improper Control of Generation of Code ('Code Injection') |
| CWE-95 | Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') |
| CWE-96 | Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection') |
| CWE-97 | Improper Neutralization of Server-Side Includes (SSI) Within a Web Page |
| CWE-98 | Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') |
| CWE-99 | Improper Control of Resource Identifiers ('Resource Injection') |
| CWE-100 | Deprecated: Was catch-all for input validation issues |
| CWE-113 | Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting') |
| CWE-116 | Improper Encoding or Escaping of Output |
| CWE-138 | Improper Neutralization of Special Elements |
| CWE-184 | Incomplete List of Disallowed Inputs |
| CWE-470 | Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection') |
| CWE-471 | Modification of Assumed-Immutable Data (MAID) |
| CWE-564 | SQL Injection: Hibernate |
| CWE-610 | Externally Controlled Reference to a Resource in Another Sphere |
| CWE-643 | Improper Neutralization of Data within XPath Expressions ('XPath Injection') |
| CWE-644 | Improper Neutralization of HTTP Headers for Scripting Syntax |
| CWE-652 | Improper Neutralization of Data within XQuery Expressions ('XQuery Injection') |
| CWE-917 | Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection') |

### **CWE-80 (Improper Neutralization of Script-Related HTML Tags in a Web Page / Basic XSS)**

### Description

The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special characters such as "<", ">", and "&" that could be interpreted as web-scripting elements when they are sent to a downstream component that processes web pages. This vulnerability allows such characters to be treated as control characters, which are executed client-side in the context of the user's session.

This vulnerability is commonly referred to as Cross-Site Scripting (XSS). Attackers exploit XSS vulnerabilities by injecting malicious scripts into web pages viewed by other users. When these scripts run in the user's browser, they can perform various malicious actions, including stealing sensitive data, manipulating user sessions, and executing unauthorized code. Properly neutralizing script-related HTML tags is crucial to prevent XSS attacks and protect user data and system integrity.

### **Business Impact**

The incorrect neutralization of script-related HTML tags in a web page can result in a significant security vulnerability known as Cross-Site Scripting (XSS). This vulnerability allows attackers to inject malicious scripts into web pages viewed by other users. When these malicious scripts execute in the user's browser, they can steal sensitive data, manipulate user sessions, deface websites, and perform other malicious actions on behalf of the attacker. The impact ranges from information disclosure and user impersonation to complete takeover of user accounts and unauthorized execution of arbitrary code. Proper neutralization of script-related tags is critical to prevent XSS attacks and safeguard user data and system integrity.

### Overview of the Target

Again, I targetted the same website as before ([FastFoodHackings](https://bugbountytraining.com/fastfoodhackings/index.php)) and as iterated previously, I am authorized to exploit it for the vulnerability since it is meant for bug bounty practice.

### Methodology/Procedure to Exploit:

This vulnerability was also found in the bookings page that we have explored before. The XSS part however was found specifically in the date picker. This was because the design of the site was such that the developer had assumed that the HTML date picker would be enough validation to sanitize the input given from the user. 

What this means is, since you cannot manually enter charectors and the only way to enter information is thru the graphic interface of the date picker, the developer assumes that is enough data sanitization. 

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2010.png)

However we can intercept the request in between thru the proxy and then modify and sent this request to the server and play around with it. 

On entering information normally, the rendered output looks like this in HTML:

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2011.png)

Specifically, we notice that the date entered is being rendered in an HTML element like so:

```html
<input type="date" class="form-control" id="date" aria-label="Username" aria-describedby="basic-addon1" value="2023-08-10" locked="">
```

Whatever we enter shows up in this section:

```html
<input type="date" class="form-control" id="date" aria-label="Username" aria-describedby="basic-addon1" value="{our entered information / text}" locked="">
```

So to design an XSS attack, we can see if we can end the HTML tag here itself and then start a new script tag there with our own javascript code. I will be trying to trigger the `print()` function which usually sends the page to the printer. This should look something like:

```html
<input type="date" class="form-control" id="date" aria-label="Username" aria-describedby="basic-addon1" value=" "><script>print()</script>" locked="">
```

So I will try to intercept the packet in between and try to send the terms `"><script>print()</script>`

To do this, I opened the same page again for another order booking, entered some random information and switched on the intercept.

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2012.png)

Then I tapped the `Reserve Booking` to catch the request in between. 

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2013.png)

Here the request being sent (line 21) is: 

```html
email=test@test.com&date=2023-08-01&userFN=Owais
```

I modified this to:

```html
email=test@test.com&date="><script>print()</script>&userFN=Owais
```

And when I forwarded this packet, the print function triggered.

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2014.png)

This means we were able to execute a script and discover a reflected XSS since the information went to the server and came back thru the form. 

On cancelling the print and checking by using inspect element, we see that the code has been injected in the page and the remaining part of the script from earlier is shown after the date picker as plain text.

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2015.png)

---

## 4. Insecure Design

Insecure design vulnerabilities stem from the inadequate consideration of security during the software design phase. These vulnerabilities can manifest as poor architecture, lack of threat modeling, and failure to address potential attack vectors during the design and planning stages.

### Impact:

Insecure design can result in fundamental flaws that are difficult to mitigate after the software is developed. Such vulnerabilities may enable various attacks, compromise user privacy, and require substantial rework to address properly.

### List of Mapped CWEs:

| CWE Code | Vulnerability Name |
| --- | --- |
| CWE-73 | External Control of File Name or Path |
| CWE-183 | Permissive List of Allowed Inputs |
| CWE-209 | Generation of Error Message Containing Sensitive Information |
| CWE-213 | Exposure of Sensitive Information Due to Incompatible Policies |
| CWE-235 | Improper Handling of Extra Parameters |
| CWE-256 | Unprotected Storage of Credentials |
| CWE-257 | Storing Passwords in a Recoverable Format |
| CWE-266 | Incorrect Privilege Assignment |
| CWE-269 | Improper Privilege Management |
| CWE-280 | Improper Handling of Insufficient Permissions or Privileges |
| CWE-311 | Missing Encryption of Sensitive Data |
| CWE-312 | Cleartext Storage of Sensitive Information |
| CWE-313 | Cleartext Storage in a File or on Disk |
| CWE-316 | Cleartext Storage of Sensitive Information in Memory |
| CWE-419 | Unprotected Primary Channel |
| CWE-430 | Deployment of Wrong Handler |
| CWE-434 | Unrestricted Upload of File with Dangerous Type |
| CWE-444 | Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') |
| CWE-451 | User Interface (UI) Misrepresentation of Critical Information |
| CWE-472 | External Control of Assumed-Immutable Web Parameter |
| CWE-501 | Trust Boundary Violation |
| CWE-522 | Insufficiently Protected Credentials |
| CWE-525 | Use of Web Browser Cache Containing Sensitive Information |
| CWE-539 | Use of Persistent Cookies Containing Sensitive Information |
| CWE-579 | J2EE Bad Practices: Non-serializable Object Stored in Session |
| CWE-598 | Use of GET Request Method With Sensitive Query Strings |
| CWE-602 | Client-Side Enforcement of Server-Side Security |
| CWE-642 | External Control of Critical State Data |
| CWE-646 | Reliance on File Name or Extension of Externally-Supplied File |
| CWE-650 | Trusting HTTP Permission Methods on the Server Side |
| CWE-653 | Insufficient Compartmentalization |
| CWE-656 | Reliance on Security Through Obscurity |
| CWE-657 | Violation of Secure Design Principles |
| CWE-799 | Improper Control of Interaction Frequency |
| CWE-807 | Reliance on Untrusted Inputs in a Security Decision |
| CWE-840 | Business Logic Errors |
| CWE-841 | Improper Enforcement of Behavioral Workflow |
| CWE-927 | Use of Implicit Intent for Sensitive Communication |
| CWE-1021 | Improper Restriction of Rendered UI Layers or Frames |
| CWE-1173 | Improper Use of Validation Framework |

### Example: CWE-840 (Business Logic Errors)

### **Description**

Weaknesses in this category identify problems that often allow attackers to manipulate the business logic of an application. These errors can have a severe impact on the application's functionality. They are challenging to detect automatically as they often involve legitimate use of the application's features. Business logic errors may exhibit patterns similar to well-known implementation and design weaknesses.

### **Business Impact**

Business logic errors can lead to significant consequences. Attackers exploiting these errors could manipulate the application's intended behavior, allowing unauthorized access to sensitive data, unauthorized transactions, or unauthorized control over system functions. This can result in financial losses, data breaches, regulatory non-compliance, reputational damage, and legal liabilities. Such errors can be difficult to identify and remediate, making them a serious concern in application security.

### Overview of the Target

For this example, I picked up a lab from [PortSwigger](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls). This the company that created BurpSuite so the target sites are very well crafted. And since this is also for Bug Bounty practice, I am authorized to pick this up for testing.

### Methodology/Procedure to Exploit:

The target site is an ecommerce application and on logging in, we have a store credit of `$100`. 

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2016.png)

Here there is a vulnerability in the add to cart feature that lets you buy items at a price you have set by yourself. 

When you normally add an item to the cart:

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2017.png)

And try to buy it, The transaction gets blocked and there’s not enough credit for the purchase.

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2018.png)

So we try adding it again but this time we intercept the data while sending it over. And we see that the price is being sent over as a parameter.

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2019.png)

So we modify it to an arbitrary integer just to see if it works and forward the request.

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2020.png)

And now when we access the cart, we see it being added for our price instead. ($10)

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2021.png)

And when we place the order, it sends back a confirmation, indicating that we have successfully exploited this application for that vulnerability. 

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2022.png)

---

## 5. Security Misconfiguration

Security misconfiguration vulnerabilities arise when system components, frameworks, or applications are not properly configured to follow security best practices. This can include leaving default credentials, unnecessary services enabled, and exposed sensitive information.

### Impact:

Security misconfiguration can lead to unauthorized access, data exposure, and other security breaches. Attackers can exploit misconfigured settings to gain control over systems, extract sensitive data, and disrupt services.

### List of Mapped CWEs:

| CWE Code | Vulnerability Name |
| --- | --- |
| CWE-2 | 7PK - Environment |
| CWE-11 | ASP.NET Misconfiguration: Creating Debug Binary |
| CWE-13 | ASP.NET Misconfiguration: Password in Configuration File |
| CWE-15 | External Control of System or Configuration Setting |
| CWE-16 | Configuration |
| CWE-260 | Password in Configuration File |
| CWE-315 | Cleartext Storage of Sensitive Information in a Cookie |
| CWE-520 | .NET Misconfiguration: Use of Impersonation |
| CWE-526 | Exposure of Sensitive Information Through Environmental Variables |
| CWE-537 | Java Runtime Error Message Containing Sensitive Information |
| CWE-541 | Inclusion of Sensitive Information in an Include File |
| CWE-547 | Use of Hard-coded, Security-relevant Constants |
| CWE-611 | Improper Restriction of XML External Entity Reference |
| CWE-614 | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute |
| CWE-756 | Missing Custom Error Page |
| CWE-776 | Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion') |
| CWE-942 | Permissive Cross-domain Policy with Untrusted Domains |
| CWE-1004 | Sensitive Cookie Without 'HttpOnly' Flag |
| CWE-1032 | OWASP Top Ten 2017 Category A6 - Security Misconfiguration |
| CWE-1174 | ASP.NET Misconfiguration: Improper Model Validation |

### **CWE-537: Java Runtime Error Message Containing Sensitive Information**

### **Description**

In many cases, attackers can exploit unhandled exception errors in java to gain unauthorized access to the system by leveraging the conditions that cause these errors.

### Business Impact

The exposure of sensitive error information in runtime error messages can have a confidentiality impact. Attackers may gain insights into the internal workings of the application, its file system structure, or other sensitive information contained within the error messages. This information could be used to formulate targeted attacks, further exploiting vulnerabilities in the application.

### Overview of the Target

The target website is an ecommerce website with different product listings. It is a website meant for bug bounty practice so I am authorized to hack into the website and/or to try to exploit common vulnerabilities.

### Methodology/Procedure to Exploit:

This vulnerability was relatively simple to exploit. All of the different products listed on the site had URLs with different product IDs being passed as parameter in `HTTP POST` method.

For example the first product 1 had the URL as:

```html
https://0ad20027040dce5d86a427a90038001.web-security-academy.net/product?productId=1
```

The 5th had a URL as: 

```html
https://0ad20027040dce5d86a427a90038001.web-security-academy.net/product?productId=5
```

So I tried putting it as an arbitrarily huge number like 9328357248 since the possiblity of those many entries existing on the database was slim. And instead of throwing a custom error message, I directly got an error response from the java runtime. 

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2023.png)

While it did contain a lot of information about the errors encountered by the internal server, It also revealed what the server is running on in the bottom line… `Apache Struts 2 2.3.31` 

A [simple google search of this server](https://www.google.com/search?q=apache+struts+2+2.3.31&oq=Apache+Struts+2+2.3.31&aqs=chrome.0.35i39i650j0i512j0i390i650.919j0j1&sourceid=chrome&ie=UTF-8) reveals that this is a very vulnerable server and has numerous vulnerabilities. Here are some CVEs with some pretty high base scores with known exploits existing.

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2024.png)

### Note:

This vulnerability also qualifies for CWE-756 (Missing Custom Error Page) and for CWE-1035 from A06:2021 (2017 Top 10 A9: Using Components with Known Vulnerabilities)  

---

## 6. Vulnerable and Outdated Components

Vulnerable and outdated components are software elements used within applications or systems that contain known security vulnerabilities or have not been updated to address security issues. Attackers can target these components to exploit known weaknesses.

### Impact:

Exploiting vulnerable and outdated components can provide attackers with access to systems, data theft, and unauthorized execution of code. These attacks can leverage well-known vulnerabilities to compromise the security of an application or system.

### List of Mapped CWEs:

| CWE Code | Vulnerability Name |
| --- | --- |
| CWE-937 | OWASP Top 10 2013: Using Components with Known Vulnerabilities |
| CWE-1035 | 2017 Top 10 A9: Using Components with Known Vulnerabilities |
| CWE-1104 | Use of Unmaintained Third Party Components |

### Example: **CWE 1035  (OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities)**

### **Summary:**

Weaknesses in this category are related to the A9 category in the OWASP Top Ten 2017, which is about using components with known vulnerabilities.

### **Business Impact:**

Using components with known vulnerabilities can significantly increase the risk of security breaches. Attackers often target well-known vulnerabilities in widely-used components to exploit weaknesses in an application. This can lead to unauthorized access, data leakage, or complete system compromise. The impact can be severe, including loss of sensitive data, reputation damage, financial losses, and legal consequences.

### Exploited Website:

Refer previous demonstration as it fits either category. The website used an older version of Apache Struts which is highly vulnerable.

![Untitled](Week%201%20Assignment%20fb7018cb51ce49d09909bc960a4b613f/Untitled%2024.png)

---

## 7. Identification and Authentication Failures

Identification and authentication failures occur when an application or system fails to properly verify the identity of users or entities. This can result from weak password policies, lack of multi-factor authentication, or other authentication-related issues.

### Impact:

These failures can lead to unauthorized access, account compromise, and identity theft. Attackers can bypass authentication mechanisms and gain unauthorized entry to systems or impersonate legitimate users.

### List of Mapped CWEs:

| CWE Code | Vulnerability Name |
| --- | --- |
| CWE-255 | Credentials Management Errors |
| CWE-259 | Use of Hard-coded Password |
| CWE-287 | Improper Authentication |
| CWE-288 | Authentication Bypass Using an Alternate Path or Channel |
| CWE-290 | Authentication Bypass by Spoofing |
| CWE-294 | Authentication Bypass by Capture-replay |
| CWE-295 | Improper Certificate Validation |
| CWE-297 | Improper Validation of Certificate with Host Mismatch |
| CWE-300 | Channel Accessible by Non-Endpoint |
| CWE-302 | Authentication Bypass by Assumed-Immutable Data |
| CWE-304 | Missing Critical Step in Authentication |
| CWE-306 | Missing Authentication for Critical Function |
| CWE-307 | Improper Restriction of Excessive Authentication Attempts |
| CWE-346 | Origin Validation Error |
| CWE-384 | Session Fixation |
| CWE-521 | Weak Password Requirements |
| CWE-613 | Insufficient Session Expiration |
| CWE-620 | Unverified Password Change |
| CWE-640 | Weak Password Recovery Mechanism for Forgotten Password |
| CWE-798 | Use of Hard-coded Credentials |
| CWE-940 | Improper Verification of Source of a Communication Channel |
| CWE-1216 | Lockout Mechanism Errors |

---

## 8. Software and Data Integrity Failures

Software and data integrity failures involve the unauthorized modification or tampering of software or data. This can occur due to insufficient integrity checks, insecure update mechanisms, or inadequate protection against malicious actors.

### Impact:

Integrity failures can lead to compromised software functionality, data corruption, and unauthorized changes to critical data. Attackers can inject malicious code, alter software behavior, and disrupt system operations.

### List of Mapped CWEs:

| CWE Code | Vulnerability Name |
| --- | --- |
| CWE-345 | Insufficient Verification of Data Authenticity |
| CWE-353 | Missing Support for Integrity Check |
| CWE-426 | Untrusted Search Path |
| CWE-494 | Download of Code Without Integrity Check |
| CWE-502 | Deserialization of Untrusted Data |
| CWE-565 | Reliance on Cookies without Validation and Integrity Checking |
| CWE-784 | Reliance on Cookies without Validation and Integrity Checking in a Security Decision |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere |
| CWE-830 | Inclusion of Web Functionality from an Untrusted Source |
| CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes |

---

## 9. Security Logging and Monitoring Failures

Security logging and monitoring failures relate to inadequate or ineffective logging and monitoring practices. This can include insufficient event tracking, improper alerting mechanisms, and lack of real-time visibility into security incidents.

### Impact:

Failure in security logging and monitoring can result in delayed or undetected security breaches. Attackers can operate undetected, exfiltrate data, and cause damage to systems without timely intervention.

### List of Mapped CWEs:

| CWE Code | Vulnerability Name |
| --- | --- |
| CWE-117 | Improper Output Neutralization for Logs |
| CWE-223 | Omission of Security-relevant Information |
| CWE-532 | Insertion of Sensitive Information into Log File |
| CWE-778 | Insufficient Logging |

---

## 10. Server-Side Request Forgery

Server-Side Request Forgery (SSRF) is a vulnerability that allows an attacker to manipulate a server into making unauthorized requests to other internal or external resources. Attackers can abuse SSRF to bypass security controls, access sensitive data, or perform actions on behalf of the server.

### Impact:

SSRF can lead to unauthorized data exposure, remote code execution, and even compromise of internal services that were not intended to be directly accessible. Attackers can use SSRF to pivot within networks or extract sensitive information.

### List of Mapped CWEs:

| CWE Code | Vulnerability Name |
| --- | --- |
| CWE-918 | Server-Side Request Forgery (SSRF) |