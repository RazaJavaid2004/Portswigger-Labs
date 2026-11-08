# PortSwigger Lab: Blind SQL Injection with Time Delays

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective

The goal of this lab is to exploit a blind SQL injection vulnerability in the `TrackingId` analytics cookie. The application does not return query results, does not alter its page content based on boolean conditions, and suppresses all database error messages. However, because the backend SQL query is executed synchronously, we can solve the lab by injecting a database-specific time delay function that forces the application to pause for **10 seconds** before responding.

## The Vulnerability Concept

Time-based blind SQL injection is used when an application completely masks both query results and database exceptions, leaving attackers without a visual or error-based oracle. If the application executes the SQL query synchronously (meaning the HTTP response waits for the database query to finish), an attacker can inject built-in database sleep functions—such as `pg_sleep(10)` in PostgreSQL, `SLEEP(10)` in MySQL, or `WAITFOR DELAY '0:0:10'` in Microsoft SQL Server. Observing a corresponding delay in the HTTP response time confirms the vulnerability and can be paired with conditional logic to extract data bit by bit.

## Step-by-Step Exploitation

### 1. Reconnaissance & Traffic Interception

I started by reviewing the lab instructions, which noted that the `TrackingId` cookie is processed synchronously by a backend SQL query and that our objective is to trigger a 10-second time delay.

![Lab Description](images/Blind%20SQL%20Injection%20with%20Time%20Delays/Lab%20Description.png)

Next, I launched the lab environment and loaded the main e-commerce storefront to generate standard HTTP traffic.

![Storefront Home](images/Blind%20SQL%20Injection%20with%20Time%20Delays/Storefront%20Home.png)

Opening Burp Suite, I navigated to the **Proxy -> HTTP history** tab and located the initial `GET /` request containing the `TrackingId` cookie (`TrackingId=dYQ85OGgOb6pASnq`).

![Proxy HTTP History](images/Blind%20SQL%20Injection%20with%20Time%20Delays/Proxy%20HTTP%20History.png)

I sent this request over to **Burp Repeater** to test time-delay payloads against the `TrackingId` cookie and monitor the response timer.

![Burp Repeater Setup](images/Blind%20SQL%20Injection%20with%20Time%20Delays/Burp%20Repeater%20Setup.png)

### 2. Injecting the Time Delay Payload

Using the SQL injection cheat sheet for reference, I tested PostgreSQL's built-in sleep function (`pg_sleep()`) concatenated into the `TrackingId` string using the `||` operator:

`TrackingId=dYQ85OGgOb6pASnq' || pg_sleep(10)--`

**How the payload works:**
* `'` closes the original `TrackingId` string literal.
* `||` concatenates the result of the `pg_sleep(10)` function into the string expression, forcing PostgreSQL to pause execution for 10 seconds.
* `--` comments out the remainder of the original SQL query so the syntax remains valid.

Sending the modified request in Burp Repeater resulted in an `HTTP/2 200 OK` response, and the response timer in the bottom-right corner confirmed a delay of **`10,708 millis`** (just over 10 seconds).

![Time Delay Confirmed in Repeater](images/Blind%20SQL%20Injection%20with%20Time%20Delays/Time%20Delay%20Confirmed%20in%20Repeater.png)

### 3. Verification

Refreshing the lab page in the browser immediately displayed the **"Congratulations, you solved the lab!"** banner, confirming the successful exploitation of the time-based blind SQL injection vulnerability.

![Lab Solved](images/Blind%20SQL%20Injection%20with%20Time%20Delays/Lab%20Solved.png)

## Remediation

To prevent time-based blind SQL injection vulnerabilities, developers must use **parameterized queries (prepared statements)** for all database operations, including those handling cookies and HTTP headers. Parameterization ensures that user-supplied input is strictly treated as a literal value rather than executable SQL syntax, preventing attackers from invoking database functions like `pg_sleep()`.