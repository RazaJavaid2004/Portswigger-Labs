# PortSwigger Lab: Blind SQL Injection with Time Delays and Information Retrieval

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective

The goal of this lab is to exploit a time-based blind SQL injection vulnerability residing in the `TrackingId` analytics cookie. The application suppresses all query results, does not alter its page content based on boolean conditions, and hides all database errors. However, because the query is executed synchronously, we can inject conditional time delays (`pg_sleep()`) to systematically infer the `administrator` password character by character and log into their account.

## The Vulnerability Concept

When an application completely masks both query output and database exceptions, attackers must rely on timing side-channels to extract data. By combining a SQL `CASE` expression with a database sleep function (such as `pg_sleep(5)` in PostgreSQL), we can instruct the database to pause execution for 5 seconds *only* when a specific condition (like checking a password length or testing a character via `SUBSTRING()`) evaluates to `TRUE`, and respond immediately (`pg_sleep(-1)` or `pg_sleep(0)`) when `FALSE`. By running single-threaded automated attacks and measuring the HTTP response times in milliseconds, we can reconstruct sensitive credentials from the database.

## Step-by-Step Exploitation & Automation Workflow

### 1. Reconnaissance & Traffic Interception

I started by reviewing the lab instructions, which noted that the `TrackingId` cookie is processed synchronously and that our objective is to extract the `administrator` password from the `users` table using conditional time delays.

![Lab Description](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Lab%20Description.png)

Next, I launched the lab environment and browsed the main e-commerce storefront to generate standard HTTP traffic.

![Storefront Home](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/StoreFront%20Home.png)

Opening Burp Suite, I inspected the **Proxy -> HTTP history** tab and located the initial `GET /` request containing the `TrackingId` cookie (`TrackingId=GFJXYEiTeQwhphUi`).

![Proxy HTTP History](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Proxy%20HTTP%20History.png)

I sent this request over to **Burp Repeater** so I could manipulate the cookie value and monitor the response time in milliseconds.

![Sending Request to Repeater](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Sending%20Request%20to%20Repeater.png)

### 2. Confirming Time-Based Injection & Conditional Logic

To verify that the backend database is PostgreSQL and executes queries synchronously, I concatenated a 5-second sleep command (`pg_sleep(5)`) into the `TrackingId` cookie:
`TrackingId=GFJXYEiTeQwhphUi' || pg_sleep(5)--`
The server returned an `HTTP/2 200 OK` after **`5,576 millis`**, confirming the time-based injection point.

![Testing 5-Second Sleep](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Testing%205-Second%20Sleep.png)

Next, I constructed a conditional `CASE` statement that triggers a 5-second delay when a condition is true (`1=1`), and no delay (`pg_sleep(-1)`) when false:
`TrackingId=GFJXYEiTeQwhphUi' || (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(-1) END)--`
Because `1=1` is true, the response took **`5,467 millis`** to return.

![True Condition Time Delay](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/True%20Condition%20Time%20Delay.png)

To verify the false branch, I changed the condition to `1=0`:
`TrackingId=GFJXYEiTeQwhphUi' || (SELECT CASE WHEN (1=0) THEN pg_sleep(5) ELSE pg_sleep(-1) END)--`
Because `1=0` is false, the server responded almost instantaneously in **`631 millis`**. This established a reliable timing oracle (`> 5000 ms` = True, `< 1000 ms` = False).

![False Condition Immediate Response](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/False%20Condition%20Immediate%20Response.png)

### 3. Verifying the `administrator` Account & Password Length Bounds

Next, I queried the `users` table to confirm that the `administrator` username exists:
`TrackingId=GFJXYEiTeQwhphUi' || (SELECT CASE WHEN (username = 'administrator') THEN pg_sleep(5) ELSE pg_sleep(-1) END FROM users)--`
The response took **`5,475 millis`**, confirming the `administrator` account is present in the `users` table.

![Confirming Administrator Account](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Confirming%20Administrator%20Account.png)

To narrow down the length of the administrator's password, I appended `AND LENGTH(password) > 5` to the condition:
`TrackingId=GFJXYEiTeQwhphUi' || (SELECT CASE WHEN (username = 'administrator' AND LENGTH(password) > 5) THEN pg_sleep(5) ELSE pg_sleep(-1) END FROM users)--`
The response took **`5,360 millis`** (True — the password is longer than 5 characters).

![Testing Password Length Greater Than 5](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Testing%20Password%20Length%20Greater%20Than%205.png)

I then tested an upper bound of `30` (`AND LENGTH(password) > 30`):
`TrackingId=GFJXYEiTeQwhphUi' || (SELECT CASE WHEN (username = 'administrator' AND LENGTH(password) > 30) THEN pg_sleep(5) ELSE pg_sleep(-1) END FROM users)--`
The response returned immediately in **`161 millis`** (False — the password is not longer than 30 characters).

![Testing Password Length Greater Than 30](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Testing%20Password%20Length%20Greater%20Than%2030.png)

### 4. Automating Password Length Discovery (Sniper)

To find the exact password length between 5 and 30, I sent the request to **Burp Intruder** for a **Sniper** attack.

![Sending Length Check to Intruder](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Sending%20Length%20Check%20to%20Intruder.png)

I placed the payload marker on the length value (`LENGTH(password) > §5§`) and configured a sequential **Numbers** payload from `5` to `30` with a step of `1`.

![Configuring Numbers Payload for Length](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Configuring%20Numbers%20Payload%20for%20Length.png)

**Crucial Step for Time-Based Attacks:** Because sending multiple concurrent requests can cause network congestion or database queuing that skews response times, I navigated to the **Resource pool** tab and created a custom pool named `delays` with **Maximum concurrent requests** set to **`1`**.

![Configuring Single-Threaded Resource Pool](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Configuring%20Single-Threaded%20Resource%20Pool.png)

Running the single-threaded attack revealed a clear boundary in the **Response received** column: payloads `5` through `19` all took over **`5,160 ms`**, whereas payload `20` and onwards dropped sharply to **`~156 ms`**. Because the password length is greater than 19 but *not* greater than 20, the password is confirmed to be **exactly 20 characters long**.

![Intruder Password Length Results](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Intruder%20Password%20Length%20Results.png)

### 5. Extracting the First Character (Sniper)

With the 20-character length confirmed, I used the `SUBSTRING()` function to test extracting the first character manually in **Burp Repeater**:
`TrackingId=GFJXYEiTeQwhphUi' || (SELECT CASE WHEN (username = 'administrator' AND SUBSTRING(password,1,1) = 'a') THEN pg_sleep(5) ELSE pg_sleep(-1) END FROM users)--`
The response returned in **`328 millis`**, meaning the first character is not `'a'`.

![Testing First Character in Repeater](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Testing%20First%20Character%20in%20Repeater.png)

I sent this request to **Burp Intruder** to brute-force the first character using a **Sniper** attack. I placed the payload marker on the character value (`SUBSTRING(password,1,1) = '§a§'`) and configured a **Brute forcer** payload with the lowercase alphanumeric character set (`abcdefghijklmnopqrstuvwxyz0123456789`) of length 1.

![Configuring Brute Forcer for First Character](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Configuring%20Brute%20Forcer%20for%20First%20Character.png)

Running the attack across all 36 characters showed that 35 of the payloads responded in ~150 ms, while payload **`x`** (Request 24) paused for **`5,153 ms`**.

![Intruder Results Identifying First Character](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Intruder%20Results%20Identifying%20First%20Character.png)

I opened Mousepad to track the 20 character positions and recorded `x` as the 1st character.

![Recording First Character in Mousepad](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Recording%20First%20Character%20in%20Mousepad.png)

### 6. Automating Full Password Extraction (Cluster Bomb)

To extract the entire 20-character password automatically, I switched Burp Intruder to a **Cluster bomb** attack and defined two payload positions—one for the character index and one for the character value:
`TrackingId=GFJXYEiTeQwhphUi' || (SELECT CASE WHEN (username = 'administrator' AND SUBSTRING(password,§1§,1) = '§a§') THEN pg_sleep(5) ELSE pg_sleep(-1) END FROM users)--`

For **Payload position 1**, I configured a sequential **Numbers** payload from `1` to `20`.

![Cluster Bomb Payload 1 Configuration](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Cluster%20Bomb%20Payload%201%20Configuration.png)

For **Payload position 2**, I configured the **Brute forcer** payload with the lowercase alphanumeric character set (`abcdefghijklmnopqrstuvwxyz0123456789`).

![Cluster Bomb Payload 2 Configuration](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Cluster%20Bomb%20Payload%202%20Configuration.png)

I launched the Cluster bomb attack (720 total requests using the single-threaded resource pool). Once completed, I sorted the results table by the **Response received** column in descending order, immediately bringing all 20 requests that triggered the `> 5,100 ms` delay to the very top of the list.

![Sorting Cluster Bomb Results by Response Time](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Sorting%20Cluster%20Bomb%20Results%20by%20Response%20Time.png)

I highlighted those top 20 delayed rows, filtered the table to show only highlighted items, and sorted by **`Payload 1`** (character position `1` through `20`) in ascending order.

![Filtering and Ordering Highlighted Characters](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Filtering%20and%20Ordering%20Highlighted%20Characters.png)

Reading down the **`Payload 2`** column sequentially from position 1 to 20 allowed me to assemble the complete 20-character administrator password in Mousepad:
`xeg1f4i79gcq7qooi36u`

![Assembling Full Password in Mousepad](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Assembling%20Full%20Password%20in%20Mousepad.png)

### 7. Authentication & Verification

With the plaintext password (`xeg1f4i79gcq7qooi36u`) fully recovered, I returned to the browser, navigated to the `/login` page, and entered the credentials for `administrator`.

![Logging in as Administrator](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Logging%20in%20as%20Administrator.png)

Upon submitting the form, the application authenticated the session, redirected me to the administrator's "My Account" page, and displayed the **"Congratulations, you solved the lab!"** banner.

![Lab Solved Confirmation](images/Blind%20SQL%20Injection%20with%20Time%20Delays%20and%20Information%20Retrieval/Lab%20Solved%20Confirmation.png)

## Remediation

To prevent time-based blind SQL injection vulnerabilities, developers must use **parameterized queries (prepared statements)** for all database operations, including those processing cookies and HTTP headers. Parameterization ensures that user-supplied input is strictly treated as literal data rather than executable SQL code, preventing attackers from injecting `CASE` expressions or invoking database sleep functions like `pg_sleep()`.