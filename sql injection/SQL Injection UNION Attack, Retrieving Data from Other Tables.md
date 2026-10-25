# PortSwigger Lab: SQL Injection UNION Attack, Retrieving Data from Other Tables

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective
The objective of this lab is to exploit a SQL injection vulnerability in the product category filter using a UNION attack. We need to retrieve all usernames and passwords from the `users` table and use that information to log in as the `administrator` user.

## The Vulnerability Concept
When an application is vulnerable to SQL injection and returns the results of its backend query in the HTTP response, an attacker can use the `UNION` operator to combine the results of the original query with results from an injected query. Once the number of columns and the text-compatible columns are determined, this technique allows direct extraction of sensitive data from other tables within the database schema.

## Step-by-Step Exploitation

### 1. Reconnaissance and Interception
I started by opening the lab and reviewing the description, which noted that a `users` table exists containing `username` and `password` columns.

![Lab Description](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Data%20from%20Other%20Tables/Lab%20Description.png)

Navigating to the main storefront, I browsed the available products.

![Storefront Home](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Data%20from%20Other%20Tables/Storefront%20Home.png)

I selected the **Tech gifts** category filter to trigger the category request.

![Category Selection](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Data%20from%20Other%20Tables/Category%20Selection.png)

Using Burp Suite, I inspected the HTTP proxy history to locate the target `GET /filter?category=Tech+gifts` request.

![Proxy History](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Data%20from%20Other%20Tables/Proxy%20History.png)

I sent this request to **Burp Repeater** for active testing.

![Burp Repeater Interface](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Data%20from%20Other%20Tables/Burp%20Repeater%20Interface.png)

### 2. Determining Column Count
Before extracting data, I needed to confirm the structure of the original query. I systematically used the `ORDER BY` technique:

*   Injecting `Tech+gifts'+order+by+1--` returned an `HTTP/2 200 OK`.

![Order By 1](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Data%20from%20Other%20Tables/Order%20by%201.png)

*   Injecting `Tech+gifts'+order+by+2--` returned an `HTTP/2 200 OK`.

![Order By 2](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Data%20from%20Other%20Tables/Order%20by%202.png)

*   Injecting `Tech+gifts'+order+by+3--` resulted in an `HTTP/2 500 Internal Server Error`.

![Order By 3 Error](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Data%20from%20Other%20Tables/Order%20by%203%20Error.png)

Because column index 3 triggered an error, I successfully confirmed that the application's original query returns exactly **2 columns**.

### 3. Querying the `users` Table
Knowing the column count and having previously confirmed that the application reflects string text in its columns, I targeted the `users` table to extract the credentials of all registered users. 

Since I had two columns available, I crafted the following UNION payload to fetch the `username` and `password` directly:
`Tech+gifts'+UNION+SELECT+username,+password+FROM+users--`

Executing this query successfully dumped the table contents directly into the response web table.

![Table Data Extraction](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Data%20from%20Other%20Tables/Table%20Data%20Extraction.png)

Scanning through the rendered records in the HTTP response, I searched for the `administrator` user.

![Column Extraction Search](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Data%20from%20Other%20Tables/Column%20Extraction%20Search.png)

I successfully located the administrator credentials injected into the HTML table structure and extracted the password.

![Extracting the Administrator Password](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Data%20from%20Other%20Tables/Extracting%20the%20Administrator%20Password.png)

### 4. Authentication and Verification
Armed with the extracted credentials, I navigated to the frontend `/login` endpoint. I entered `administrator` as the username along with the newly acquired password.

![Login Page](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Data%20from%20Other%20Tables/Login%20Page.png)

Upon submission, the application authenticated the session and redirected me to the "My Account" dashboard, triggering the "Congratulations, you solved the lab!" banner.

![Solved Lab Banner](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Data%20from%20Other%20Tables/Solved%20Lab%20Banner.png)

## Remediation
To mitigate SQL injection vulnerabilities, developers must adopt parameterized queries (prepared statements) for all database interactions involving user-supplied input. This ensures that the database driver treats user input strictly as data literals, completely neutralizing attempts to manipulate query logic or append unauthorized `UNION SELECT` statements.