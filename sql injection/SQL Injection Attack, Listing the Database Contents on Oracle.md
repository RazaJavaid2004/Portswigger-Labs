# PortSwigger Lab: SQL Injection Attack, Listing the Database Contents on Oracle

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective
The objective of this lab is to exploit a SQL injection vulnerability in the product category filter to enumerate the backend Oracle database. We must locate a hidden user table, extract the column names, retrieve the `administrator` credentials, and log in.

![Lab Description](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Oracle/Lab%20Description.png)

## The Vulnerability Concept
Unlike MySQL or Microsoft SQL Server, Oracle databases require a `FROM` clause in every `SELECT` statement. When crafting `UNION SELECT` payloads for Oracle, attackers must use the built-in `dual` dummy table (e.g., `UNION SELECT NULL FROM dual`). To enumerate database structure, attackers query Oracle's metadata tables: `all_tables` (to list tables) and `all_tab_columns` (to list columns).

## Step-by-Step Exploitation

### 1. Interception and Column Enumeration
I started by navigating the application and selecting the "Toys & Games" category. 

![Shop Front Page](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Oracle/Shop%20Front%20Page.png)

![Category Selection](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Oracle/Category%20Selection.png)

In Burp Suite, I intercepted the `GET /filter?category=Toys+%26+Games` request and sent it to Repeater.

![Intercepted Request](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Oracle/Intercepted%20Request.png)

![Repeater View](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Oracle/Repeater%20View.png)

To determine the number of columns returned by the query, I used the `ORDER BY` technique:
*   `Toys+%26+Games'+order+by+1--` returned `HTTP/2 200 OK`.

![Order By 1](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Oracle/Order%20By%201.png)

*   `Toys+%26+Games'+order+by+2--` returned `HTTP/2 200 OK`.

![Order By 2](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Oracle/Order%20By%202.png)

*   `Toys+%26+Games'+order+by+3--` returned `HTTP/2 500 Internal Server Error`.

![Order By 3 Error](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Oracle/Order%20By%203%20Error.png)

This confirms the underlying query returns exactly two columns.

### 2. Verifying String Data Types
Because this is an Oracle database, I verified that both columns can hold string data by querying the `dual` table. I used the payload:
`Toys+%26+Games'+UNION+SELECT+'abc','def'+FROM+dual--`

The response reflected `abc` and `def` on the page, confirming both columns accept strings.

![String Verification](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Oracle/String%20Verification.png)

### 3. Enumerating the Table Name
To find the table containing user credentials, I queried Oracle's `all_tables` view. I injected the following payload:
`Toys+%26+Games'+UNION+SELECT+table_name,+NULL+FROM+all_tables--`

Scanning the HTTP response, I located a dynamically generated table name that looked relevant: `USERS_UVYXIP`.

![Table Name Extraction](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Oracle/Table%20Name%20Extraction.png)

### 4. Enumerating the Column Names
With the target table identified, I queried `all_tab_columns` to find the exact column names for usernames and passwords within that specific table. The payload used was:
`Toys+%26+Games'+UNION+SELECT+column_name,+NULL+FROM+all_tab_columns+WHERE+table_name='USERS_UVYXIP'--`

The response revealed two crucial, dynamically generated column names: `USERNAME_ZLLYOZ` and `PASSWORD_UZGQJR`.

![Column Name Extraction](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Oracle/Column%20Name%20Extraction.png)

### 5. Data Extraction
Armed with the exact table and column names, I crafted the final payload to extract the administrator's credentials. I placed the username column in the first output and the password column in the second:
`Toys+%26+Games'+UNION+SELECT+USERNAME_ZLLYOZ,+PASSWORD_UZGQJR+FROM+USERS_UVYXIP--`

The query executed successfully, dumping the credentials into the HTML response. I copied the administrator's password: `5br1oiw25kvkp8452te6`.

![Data Extraction](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Oracle/Data%20Extraction.png)

### 6. Authentication and Verification
I navigated to the `/login` endpoint on the frontend application. Using `administrator` and the extracted password, I successfully authenticated.

![Login Page](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Oracle/Login%20Page.png)

This granted access to the "My Account" dashboard and triggered the "Congratulations, you solved the lab!" banner.

![Solved Lab Banner](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Oracle/Solved%20Lab%20Banner.png)

## Remediation
To defend against this systematic database enumeration and extraction, applications must implement parameterized queries (prepared statements) for all user-supplied input. Parameterization ensures that strings passed to the `category` filter are treated strictly as literal data rather than executable SQL commands, neutralizing UNION attacks entirely.