# PortSwigger Lab: SQL Injection with Filter Bypass via XML Encoding

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective
The goal of this lab is to exploit a SQL injection vulnerability in the stock check feature. A Web Application Firewall (WAF) blocks standard injection attempts, so we must bypass it using XML encoding to retrieve the `administrator` credentials from the `users` table and log in.

![Lab Description](images/SQL%20Injection%20with%20Filter%20Bypass%20via%20XML%20Encoding/lab%20description.png)

## The Vulnerability Concept
The application accepts user input in XML format to process stock check requests. It employs a WAF to detect and block common SQL injection keywords (like `UNION` or `SELECT`) in plaintext. However, many XML parsers automatically decode XML entities (such as hexadecimal encoding) *before* passing the data to the backend application. By obfuscating our SQL payload using XML hex entities, the payload slips past the WAF but is decoded and executed by the backend database.

## Step-by-Step Exploitation

### 1. Reconnaissance and Normal Functionality
To understand the application's flow, I navigated to the main storefront and selected the first product to view its details. 

![Shop Main Page](images/SQL%20Injection%20with%20Filter%20Bypass%20via%20XML%20Encoding/shop%20main%20page.png)

![Product Details](images/SQL%20Injection%20with%20Filter%20Bypass%20via%20XML%20Encoding/product%20details.png)

At the bottom of the product page, there is a "Check stock" feature. I intercepted this interaction using Burp Suite. 

![Stock Check Feature](images/SQL%20Injection%20with%20Filter%20Bypass%20via%20XML%20Encoding/stock%20check%20feature.png)

Looking at the `POST /product/stock` request in Burp, the application sends the data to the server in XML format. The standard request looks like this:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```

![Intercepted XML Request](images/SQL%20Injection%20with%20Filter%20Bypass%20via%20XML%20Encoding/intercepted%20xml%20request.png)

### 2. Hitting the WAF
I sent this request to Burp Repeater to test for SQL injection. I appended a standard UNION-based payload to the `<storeId>` parameter: `1 UNION SELECT NULL`. 

The server responded with an `HTTP/2 403 Forbidden` status and the message `"Attack detected"`. This confirmed that a WAF was actively monitoring the input for SQL injection signatures.

![WAF Block Response](images/SQL%20Injection%20with%20Filter%20Bypass%20via%20XML%20Encoding/WAF%20block%20response.png)

### 3. Bypassing the WAF via XML Encoding
To circumvent the WAF, I used the Burp Suite extension **Hackvertor** to apply XML Hex Entity encoding to my payload. 

By wrapping the payload in Hackvertor tags `<@hex_entities>1 UNION SELECT NULL<@/hex_entities>`, the payload was sent to the server in a hexadecimal format that the WAF did not recognize. The XML parser decoded it on the backend, resulting in a successful `HTTP/2 200 OK` response returning `14 null`.

![Hackvertor Bypass](images/SQL%20Injection%20with%20Filter%20Bypass%20via%20XML%20Encoding/hackvector%20bypass.png)

### 4. Data Extraction
With the WAF bypassed, I modified the query to extract the credentials. Initially, I tested the column structure. 

![Testing Query Structure](images/SQL%20Injection%20with%20Filter%20Bypass%20via%20XML%20Encoding/testing%20query%20structure.png)

Since the original query likely only returns a single column for the stock count, I needed to concatenate the `username` and `password` fields from the `users` table into a single string to retrieve them simultaneously. I crafted the following payload and encoded it again:
`1 UNION SELECT username || ' ' || password FROM users`

This successfully retrieved the user credentials, displaying them directly in the HTTP response. I located the administrator's password in the output: `92rp0hjvq54c8zfuevgb`.

![Data Extraction Success](images/SQL%20Injection%20with%20Filter%20Bypass%20via%20XML%20Encoding/data%20exfiltration%20success.png)

### 5. Authentication and Verification
Armed with the extracted password, I navigated back to the frontend `/login` page. I entered `administrator` as the username and the stolen password.

![Login Form](images/SQL%20Injection%20with%20Filter%20Bypass%20via%20XML%20Encoding/login%20form.png)

The application authenticated the session and redirected me to the "My Account" dashboard, successfully solving the lab.

![Solved Lab Banner](images/SQL%20Injection%20with%20Filter%20Bypass%20via%20XML%20Encoding/solved%20lab%20banner.png)

## Remediation
To prevent this attack, defense-in-depth is required. WAFs should be configured to decode XML entities before analyzing the data stream for malicious payloads. Furthermore, the backend application must still implement parameterized queries (prepared statements) when parsing the XML nodes, ensuring that even if an obfuscated payload reaches the backend, it is treated safely as a string literal rather than executable code.