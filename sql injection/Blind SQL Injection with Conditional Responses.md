# PortSwigger Lab: Blind SQL Injection with Conditional Responses

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective

The goal of this lab is to exploit a blind SQL injection vulnerability residing within the `TrackingId` cookie. Because the application does not explicitly return database records or error messages, we must leverage conditional logic and observe the appearance or disappearance of the `Welcome back!` message to systematically extract the administrator's password.

## The Vulnerability Concept

Blind SQL injection occurs when an application is vulnerable to SQL injection, but its HTTP responses remain identical regardless of whether a query returns records or throws an error. Attackers bypass this by forcing the database to evaluate conditional queries, evaluating differences in application behavior (such as custom greeting banners, missing elements, or varying response lengths). In this lab, if the injected SQL statement evaluates to `TRUE`, the application response includes the string `Welcome back!`; if `FALSE`, the message is omitted.

## Step-by-Step Exploitation & Automation Workflow

### 1. Initial Reconnaissance & Interception

I started by reviewing the lab brief, which established that the application uses a tracking cookie for analytics and displays a `Welcome back` message if the SQL query returns any rows.

![Lab Description](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Lab%20Description.png)

Next, I launched the lab environment and browsed the main storefront page to observe the application's baseline behavior.

![Storefront Initial Load](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Storefront%20Initial%20Load.png)

Refreshing the page or clicking around generated a tracking session, causing the `Welcome back!` banner to appear near the top navigation bar.

![Storefront Welcome Back Banner](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Storefront%20Welcome%20Back%20Banner.png)

Using Burp Suite, I inspected the **Proxy HTTP history** to capture the `GET /` request and isolate the `TrackingId` cookie parameter (`TrackingId=MKphLJgPOwKMxkly`).

![Burp Proxy HTTP History](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Burp%20Proxy%20HTTP%20History.png)

I sent this request over to **Burp Repeater** so I could manipulate the `TrackingId` cookie and observe the raw HTML responses directly.

![Request in Burp Repeater](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Request%20in%20Burp%20Repeater.png)

### 2. Validating the Boolean Injection Vector

To test if the `TrackingId` cookie was vulnerable to SQL injection, I injected a single quote (`'`) right after the cookie value (`TrackingId=MKphLJgPOwKMxkly'`) to intentionally break the query syntax. Searching the response for `welcome` yielded 0 matches.

![Testing Single Quote Injection](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Testing%20Single%20Quote%20Injection.png)

Next, I injected a boolean condition that always evaluates to true (`TrackingId=MKphLJgPOwKMxkly'+AND+1=1--`). The server returned a `200 OK` and rendered the `Welcome back!` message in the HTML, confirming that our injected syntax is being evaluated by the database.

![Boolean True Condition 1=1](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Boolean%20True%20Condition%201=1.png)

To be completely certain, I injected a false boolean condition (`TrackingId=MKphLJgPOwKMxkly'+AND+1=2--`). As expected, the `Welcome back!` message vanished completely (0 matches). This behavioral difference gives us a reliable boolean oracle to extract data.

![Boolean False Condition 1=2](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Boolean%20False%20Condition%201=2.png)

### 3. Confirming the `users` Table and Target Account

Before attempting to extract a password, I needed to verify that the `users` table exists and that I could query it using a subquery. I injected:
`TrackingId=MKphLJgPOwKMxkly'+AND+(SELECT+'x'+FROM+users+LIMIT+1)='x'--`
The `Welcome back!` message appeared, confirming the `users` table is accessible.

![Confirming Users Table Exists](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Confirming%20Users%20Table%20Exists.png)

Next, I verified that the `administrator` account exists within the `users` table by injecting:
`TrackingId=MKphLJgPOwKMxkly'+AND+(SELECT+username+FROM+users+WHERE+username='administrator')='administrator'--`
Once again, the response contained `Welcome back!`, confirming `administrator` is a valid username.

![Confirming Administrator User Exists](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Confirming%20Administrator%20User%20Exists.png)

### 4. Enumerating the Password Length

To extract the administrator's password, I first needed to determine its exact character length using the `LENGTH()` function. I tested if the password was greater than 1 character:
`TrackingId=MKphLJgPOwKMxkly'+AND+(SELECT+username+FROM+users+WHERE+username='administrator'+AND+LENGTH(password)>1)='administrator'--`
This returned `Welcome back!` (True).

![Testing Password Length Greater Than 1](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Testing%20Password%20Length%20Greater%20Than%201.png)

I then tested an upper bound to see if the password was greater than 30 characters:
`TrackingId=MKphLJgPOwKMxkly'+AND+(SELECT+username+FROM+users+WHERE+username='administrator'+AND+LENGTH(password)>30)='administrator'--`
This returned 0 matches for `Welcome back!` (False), meaning the password length is somewhere between 2 and 30 characters.

![Testing Password Length Greater Than 30](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Testing%20Password%20Length%20Greater%20Than%2030.png)

Rather than guessing manually in Repeater, I sent the request to **Burp Intruder** to automate the length discovery using a **Sniper** attack. I placed the payload marker on the length value (`LENGTH(password)>§1§`) and configured a sequential **Numbers** payload from `1` to `30`.

![Intruder Sniper Setup for Length](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Intruder%20Sniper%20Setup%20for%20Length.png)

I started the attack and monitored the results table. Notice how payloads `1` through `19` returned a response length of `11608`, while payload `20` and onwards dropped to a response length of `11547`.

![Intruder Length Attack Results](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Intruder%20Length%20Attack%20Results.png)

Filtering the Intruder results by the expression `welcome` confirmed that `LENGTH(password)>19` was the highest true statement (`Welcome back!` present). Because the password is greater than 19 characters but *not* greater than 20 characters, the password is confirmed to be **exactly 20 characters long**.

![Confirming Exact Password Length is 20](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Confirming%20Exact%20Password%20Length%20is%2020.png)

### 5. Extracting the First Character (Sniper)

With the 20-character length confirmed, I used the `SUBSTRING()` function to test extracting individual characters. First, I set up a **Sniper** attack in Intruder to find just the first character:
`TrackingId=MKphLJgPOwKMxkly'+AND+(SELECT+SUBSTRING(password,1,1)+FROM+users+WHERE+username='administrator')='§a§'--`
I configured a **Brute forcer** payload using the alphanumeric character set (`abcdefghijklmnopqrstuvwxyz0123456789`) with a min/max length of 1.

![Intruder Sniper Setup for First Character](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Intruder%20Sniper%20Setup%20for%20First%20Character.png)

Running the 36-request attack tested every possible lowercase letter and digit for position 1. Looking at the raw results table, almost all requests returned a length of `11547`, except for payload `6`, which stood out with a length of `11608`.

![First Character Attack Results](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/First%20Character%20Attack%20Results.png)

Applying the `welcome` filter in the Intruder results window isolated payload `6` and showed the `Welcome back!` banner in the response tab, confirming the first character of the password is `6`.

![Filtering First Character Result](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Filtering%20First%20Character%20Result.png)

I double-checked this finding back in **Burp Repeater** by manually testing `SUBSTRING(password,1,1)='6'`, which returned `Welcome back!`.

![Verifying First Character in Repeater](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Verifying%20First%20Character%20in%20Repeater.png)

I opened a text editor (Mousepad) and jotted down the 20 character positions, recording `6` at position 1.

![Recording First Character in Text Editor](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Recording%20First%20Character%20in%20Text%20Editor.png)

### 6. Automating Full Password Extraction (Cluster Bomb)

Testing all 20 positions one by one with Sniper would be tedious, so I switched Burp Intruder to a **Cluster bomb** attack to extract the remaining 19 characters in a single automated run.

I set two payload positions in the cookie: one for the character index and one for the character value:
`TrackingId=MKphLJgPOwKMxkly'+AND+(SELECT+SUBSTRING(password,§2§,1)+FROM+users+WHERE+username='administrator')='§a§'--`

For **Payload position 1**, I configured a sequential **Numbers** payload from `2` to `20` (since we already know position 1 is `6`).

![Cluster Bomb Payload 1 Configuration](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Cluster%20Bomb%20Payload%201%20Configuration.png)

For **Payload position 2**, I configured the **Brute forcer** payload with the full lowercase alphanumeric set (`abcdefghijklmnopqrstuvwxyz0123456789`).

![Cluster Bomb Payload 2 Configuration](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Cluster%20Bomb%20Payload%202%20Configuration.png)

I launched the Cluster bomb attack (684 total requests), allowing Intruder to iterate through every character possibility across positions 2 through 20.

![Cluster Bomb Attack Running](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Cluster%20Bomb%20Attack%20Running.png)

Once the attack finished, I applied the `welcome` filter to display only the requests that triggered the `Welcome back!` response. Ordering the results by `Payload 1` (position) allowed me to read `Payload 2` (character) sequentially and assemble the full 20-character password in my text editor:
`66c1zo1vhvj77a8fifr7`

![Compiling Extracted Password from Cluster Bomb](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Compiling%20Extracted%20Password%20from%20Cluster%20Bomb.png)

### 7. Authentication and Verification

With the plaintext password (`66c1zo1vhvj77a8fifr7`) fully reconstructed, I returned to the browser, navigated to the `/login` page, and entered the credentials for `administrator`.

![Logging In as Administrator](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Logging%20In%20as%20Administrator.png)

Upon submitting the form, the application authenticated the session, redirected me to the "My Account" page, and displayed the **"Congratulations, you solved the lab!"** banner.

![Lab Solved Confirmation](images/Blind%20SQL%20Injection%20with%20Conditional%20Responses/Lab%20Solved%20Confirmation.png)

## Remediation

To completely eliminate blind SQL injection vulnerabilities, developers must refactor application code to use **parameterized queries (prepared statements)** for all dynamic database lookups. This ensures user-supplied inputs - including background analytics tracking cookies and HTTP headers - are strictly treated as literal string data by the database engine rather than executable SQL statements.