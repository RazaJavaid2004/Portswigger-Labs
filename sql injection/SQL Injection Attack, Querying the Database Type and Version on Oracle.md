# PortSwigger Lab: SQL Injection Attack, Querying the Database Type and Version on Oracle

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective
The goal of this lab is to exploit a SQL injection vulnerability in the product category filter to retrieve and display the Oracle database version string. 

![Lab Description](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20Oracle/Lab%20Description.png)

## The Vulnerability Concept
The application concatenates user input directly into the SQL query used to filter products by category. Because the backend database is Oracle, standard SQL injection payloads must be slightly modified. Specifically, Oracle databases require all `SELECT` statements to include a `FROM` clause. If we are injecting a payload that does not query a specific table, we must use the built-in dummy table `dual`. Furthermore, Oracle database version information is stored in the `v$version` table.

## Step-by-Step Exploitation

### 1. Reconnaissance
I navigated to the main lab page and clicked on the "Clothing, shoes and accessories" category to observe the application's routing. 

![Shop Main Page](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20Oracle//Shop%20Main%20Page.png)

I intercepted the traffic using Burp Suite and located the `GET /filter?category=...` request in the Proxy HTTP history.

![Intercepted Request](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20Oracle/Intercepted%20Request.png)

I then sent this request to Repeater for testing.

![Repeater Base Request](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20Oracle/Repeater%20Base%20Request.png)

### 2. Determining the Number of Columns
Before I could extract data, I needed to determine how many columns the original query returned. I used the `ORDER BY` technique, injecting payloads into the `category` parameter.

*   Testing 1 column: `'+order+by+1+--` resulted in a `200 OK`.
![Order By 1](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20Oracle/Order%20By%201.png)

*   Testing 2 columns: `'+order+by+2+--` resulted in a `200 OK`.
![Order By 2](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20Oracle/Order%20By%202.png)

*   Testing 3 columns: `'+order+by+3+--` resulted in a `500 Internal Server Error`.
![Order By 3](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20Oracle/Order%20By%203.png)

The error on the 3rd column confirmed that the original query returns exactly **two** columns.

### 3. Determining Column Data Types
Next, I needed to verify which of the two columns could hold string data, as the database version is a string. Because this is an Oracle database, I had to query the `dual` table.

I injected the following UNION payload to test both columns for string compatibility:
`'+UNION+SELECT+'abc','def'+FROM+dual--`

The server responded with a `200 OK`, and the strings `abc` and `def` were rendered in the HTML table on the response page. This confirmed both columns accept string data.

![Testing Data Types](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20Oracle/Testing%20Data%20Types.png)

### 4. Extracting the Database Version
With the structure mapped out, I replaced my dummy strings with a query to the `v$version` table. The payload used was:
`'+UNION+SELECT+banner,+NULL+FROM+v$version--`

*Note: I queried the `banner` column from `v$version` into the first column and passed `NULL` into the second column.*

The request was successful, and the HTTP response leaked the Oracle database version strings directly into the HTML (e.g., `Oracle Database 11g Express Edition...`).

![Extracting Oracle Version](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20Oracle/Extracting%20Oracle%20Version.png)

### 5. Verification
Applying the payload or viewing the rendered response in the browser triggered the success state for the lab.

![Solved Lab Banner](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20Oracle/Solved%20Lab%20Banner.png)

## Remediation
To prevent this vulnerability, the application must use parameterized queries (prepared statements) instead of dynamically concatenating the `category` input string. This ensures the database driver treats the user's input safely as data rather than executable SQL syntax, neutralizing the `UNION` attack regardless of the underlying database engine.