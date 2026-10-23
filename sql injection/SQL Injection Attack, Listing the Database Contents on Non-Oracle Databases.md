# PortSwigger Lab: SQL Injection Attack, Listing the Database Contents on Non-Oracle Databases

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective
The goal of this lab is to exploit a SQL injection vulnerability in the product category filter to retrieve the `administrator` credentials. Since the table names and column names are uniquely generated for each lab instance, we must systematically query the database's `information_schema` to locate the correct table and columns before extracting the data.

![Lab Description](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Non-Oracle%20Databases/Lab%20Description.png)

## The Vulnerability Concept
Modern non-Oracle relational databases (like PostgreSQL, MySQL, and Microsoft SQL Server) utilize a standardized metadata structure called the `information_schema`. 

When an attacker discovers a UNION-based SQL injection vulnerability, they can query `information_schema.tables` to list all tables in the database. Once a target table (like a users table) is identified, they can query `information_schema.columns` to find the exact column names. This turns a blind structural attack into a highly targeted data breach.

## Step-by-Step Exploitation

### 1. Reconnaissance and Interception
I started by reviewing the lab brief and browsing the main storefront to understand the application layout.

![Main Storefront](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Non-Oracle%20Databases/Main%20Storefront.png)

Clicking on the "Accessories" category applied a filter, adding `?category=Accessories` to the URL. 

![Accessories Category](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Non-Oracle%20Databases/Accessories%20Category.png)

I intercepted this request in Burp Suite's HTTP History and sent it to Repeater to test for SQL injection vulnerabilities.

![Intercepted Request](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Non-Oracle%20Databases/Intercepted%20Request.png)

![Repeater Baseline Request](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Non-Oracle%20Databases/Repeater%20Baseline%20Request.png)

### 2. Enumerating the Query Structure
Before extracting data, I needed to determine how many columns the backend query returns. I used the `ORDER BY` technique:

*   `Accessories'+order+by+1--` returned `200 OK`.

![Order By 1](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Non-Oracle%20Databases/Order%20By%201.png)

*   `Accessories'+order+by+2--` returned `200 OK`.

![Order By 2](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Non-Oracle%20Databases/Order%20By%202.png)

*   `Accessories'+order+by+3--` returned a `500 Internal Server Error`.

![Order By 3 Error](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Non-Oracle%20Databases/Order%20By%203%20Error.png)

This confirmed the query returns exactly **two columns**. 

Next, I tested both columns to ensure they could hold string data, which is necessary for extracting text-based database names and credentials. I injected:
`Accessories'+UNION+SELECT+'abc','def'--`
Both strings successfully rendered in the HTTP response, confirming both columns accept text data.

![String Data Verification](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Non-Oracle%20Databases/String%20Data%20Verification.png)

### 3. Enumerating Database Tables
With the structure confirmed, I queried the `information_schema.tables` view to find the table containing user credentials. Since I only have two columns, I requested the `table_name` in the first column and `NULL` in the second:

`Accessories'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--`

Scanning through the response, I identified a custom-named users table: `users_wmfjfo`.

![Finding the Users Table](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Non-Oracle%20Databases/Finding%20the%20Users%20Table.png)

### 4. Enumerating Table Columns
Now that I had the table name (`users_wmfjfo`), I queried the `information_schema.columns` view to find the specific column names within that table:

`Accessories'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_wmfjfo'--`

The response revealed two crucial columns: `username_tvlvnd` and `password_dceect`.

![Finding the Columns](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Non-Oracle%20Databases/Finding%20the%20Columns.png)

### 5. Data Extraction
Armed with the exact table and column names, I crafted the final payload to extract the administrator's credentials. I placed the username column in the first output and the password column in the second output:

`Accessories'+UNION+SELECT+username_tvlvnd,+password_dceect+FROM+users_wmfjfo--`

The query executed successfully, dumping the user credentials directly into the HTML response. I copied the administrator's password: `7ro7r7k8nerooo9wulgv`.

![Extracting Credentials](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Non-Oracle%20Databases/Extracting%20Credentials.png)

### 6. Authentication and Verification
I navigated to the `/login` endpoint on the frontend application. 

![Login Page](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Non-Oracle%20Databases/Login%20Page.png)

Using `administrator` and the extracted password, I successfully authenticated, accessing the "My Account" dashboard and triggering the "Congratulations, you solved the lab!" banner.

![Lab Solved](images/SQL%20Injection%20Attack,%20Listing%20the%20Database%20Contents%20on%20Non-Oracle%20Databases/Lab%20Solved.png)

## Remediation
To defend against this systematic database enumeration and extraction, applications must implement **parameterized queries (prepared statements)** for all user-supplied input. Parameterization ensures that strings passed to the `category` filter are treated strictly as literal data rather than executable SQL commands, neutralizing UNION attacks entirely.