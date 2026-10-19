# PortSwigger Lab: SQL Injection Attack, Querying the Database Type and Version on MySQL and Microsoft

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective
The objective of this lab is to exploit a SQL injection vulnerability within the product category filter using a UNION attack. To successfully complete the lab, we must retrieve and display the database version string, which in this specific instance is `'8.0.42-0ubuntu0.20.04.1'`.

![Lab Description](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20MySQL%20and%20Microsoft/Lab%20Description.png)

## The Vulnerability Concept
Different database management systems (DBMS) have slightly different SQL syntaxes and built-in functions. When performing a UNION-based SQL injection, it is often necessary to identify the backend database to tailor your payloads correctly. 

For example, Microsoft SQL Server and MySQL both use `@@version` to retrieve the database version, and they both accept `#` (URL encoded as `%23`) as a comment indicator. By injecting this specific function, we can force the database to return its version details directly to the frontend application.

## Step-by-Step Exploitation

### 1. Intercepting the Target Request
To begin, I reviewed the lab description and the target version string required to pass the lab.

![Target Version String](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20MySQL%20and%20Microsoft/Target%20Version%20String.png)

I browsed the main application page and clicked on the "Corporate gifts" category to apply a filter. This action triggered a `GET` request to `/filter?category=Corporate+gifts`, which I intercepted in Burp Suite's HTTP history.

![Intercepted HTTP History](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20MySQL%20and%20Microsoft/Intercepted%20HTTP%20History.png)

I sent this request to Burp Repeater to systematically test the category parameter for SQL injection.

![Request in Repeater](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20MySQL%20and%20Microsoft/Request%20in%20Repeater.png)

### 2. Comment Syntax and Column Enumeration
My first step was to determine the number of columns returned by the backend SQL query using the `ORDER BY` clause. 

Initially, I tested the payload `Corporate+gifts'+order+by+1--` (using a standard double-dash comment), but the server responded with an `HTTP/2 500 Internal Server Error`. MySQL requires a space after the double dashes for it to be recognized as a comment, or alternatively, a hash `#` symbol. 

![Failed Comment Syntax](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20MySQL%20and%20Microsoft/Failed%20Comment%20Syntax.png)

Switching to the hash symbol (URL encoded as `%23`), I injected `Corporate+gifts'+order+by+1%23` and received an `HTTP/2 200 OK` response.

![Order By 1 Success](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20MySQL%20and%20Microsoft/Order%20By%201%20Success.png)

I incremented the column count to test the limits:
*   `Corporate+gifts'+order+by+2%23` returned `HTTP/2 200 OK`.

![Order By 2 Success](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20MySQL%20and%20Microsoft/Order%20By%202%20Success.png)

*   `Corporate+gifts'+order+by+3%23` resulted in an `HTTP/2 500 Internal Server Error`.

![Order By 3 Error](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20MySQL%20and%20Microsoft/Order%20By%203%20Error.png)

This confirmed the database query returns exactly **two columns**.

### 3. Verifying String Data Types
Next, I needed to ensure these two columns could hold string data, which is required to display the version text. I crafted a UNION SELECT payload replacing the columns with arbitrary string values:
`Corporate+gifts'+UNION+SELECT+'abc','def'%23`

The server returned a `200 OK`, and the strings `abc` and `def` were successfully reflected in the HTML response's table elements.

![String Verification](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20MySQL%20and%20Microsoft/String%20Verification.png)

### 4. Extracting the Database Version
Knowing that the application supports two string columns and operates on a MySQL or Microsoft backend, I replaced the first string with the `@@version` function and nullified the second column:
`Corporate+gifts'+UNION+SELECT+@@version,+NULL%23`

Executing this payload successfully extracted the version string, displaying `8.0.42-0ubuntu0.20.04.1` in the response body.

![Extracting Version String](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20MySQL%20and%20Microsoft/Extracting%20Version%20String.png)

### 5. Verification
Returning to the browser, the application displayed the "Congratulations, you solved the lab!" banner, confirming the successful exploitation and extraction of the database version.

![Solved Lab Banner](images/SQL%20Injection%20Attack,%20Querying%20the%20Database%20Type%20and%20Version%20on%20MySQL%20and%20Microsoft/Solved%20Lab%20Banner.png)

## Remediation
To mitigate this SQL injection vulnerability, the application should implement parameterized queries (prepared statements). Parameterization ensures that user input passed through the `category` filter is safely treated as a string literal by the database driver, stripping its ability to alter the query logic or execute injected functions like `@@version`.