# PortSwigger Lab: SQL Injection UNION Attack, Retrieving Multiple Values in a Single Column

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective
The objective of this lab is to exploit a SQL injection vulnerability in the product category filter. The query only returns a single column that accepts string data, so we must use string concatenation to retrieve both the usernames and passwords from the `users` table simultaneously, and then log in as the `administrator`.

## The Vulnerability Concept
In a `UNION` SQL injection attack, the injected query must return the same number of columns with compatible data types as the original query. If the original query only has *one* column capable of holding text data, you cannot extract two text fields (like a username and a password) in separate columns. 

To bypass this limitation, attackers can use string concatenation to merge multiple columns into a single string output. Depending on the database, this is done using operators like `||` (PostgreSQL, Oracle, SQLite), `+` (Microsoft SQL Server), or the `CONCAT()` function (MySQL). For example: `username || '~' || password`.

## Step-by-Step Exploitation

### 1. Reconnaissance and Interception
I began by reviewing the lab instructions, which mentioned a `users` table containing `username` and `password` columns.

![Lab Description](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Lab%20Description.png)

I navigated to the main storefront to interact with the application.

![Storefront Home](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Storefront%20Home.png)

Clicking on the **Pets** category applied a filter, altering the URL to include `?category=Pets`.

![Category Filter Selection](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Category%20Filter%20Selection.png)

Using Burp Suite, I monitored the HTTP history to locate the corresponding `GET /filter?category=Pets` request.

![Proxy History](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Proxy%20History.png)

I sent this request to **Burp Repeater** to rapidly test for SQL injection payloads.

![Burp Repeater Interface](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Burp%20Repeater%20Interface.png)

### 2. Determining the Column Count
To structure my UNION attack, I first needed to figure out how many columns the backend query was returning. I used the `ORDER BY` technique:

*   Injecting `Pets'+order+by+1--` returned `HTTP/2 200 OK`.

![Order By 1](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Order%20By%201.png)

*   Injecting `Pets'+order+by+2--` returned `HTTP/2 200 OK`.

![Order By 2](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Order%20By%202.png)

*   Injecting `Pets'+order+by+3--` resulted in an `HTTP/2 500 Internal Server Error`.

![Order By 3 Error](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Order%20By%203%20Error.png)

The error at index 3 confirmed that the query returns exactly **2 columns**.

### 3. Finding the Text-Compatible Column
Next, I needed to determine which of these two columns could hold string data. 

*   I tested the first column: `Pets'+UNION+SELECT+'abc',+NULL--`. This resulted in a `500 Internal Server Error`, indicating the first column does not accept strings.

![Testing Column 1](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Testing%20Column%201.png)

*   I tested the second column: `Pets'+UNION+SELECT+NULL,+'abc'--`. This returned a `200 OK`, successfully reflecting the string `abc` onto the page. This confirmed I had **one** available string column to work with.

![Testing Column 2](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Testing%20Column%202.png)

### 4. Database Enumeration (Optional but Thorough)
Although the lab description provided the table and column names, I proceeded to systematically verify the database structure by querying the `information_schema` into my single text column.

First, I extracted the table names:
`Pets'+UNION+SELECT+NULL,+table_name+FROM+information_schema.tables--`
Scanning the response confirmed the existence of the `users` table.

![Extracting Table Names](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Extracting%20Table%20Names.png)

Next, I queried the column names for that specific table (though not strictly required since we knew them, it confirms the schema):
`Pets'+UNION+SELECT+NULL,+column_name+FROM+information_schema.columns--` (or filtering by table name).

![Extracting Column Names 1](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Extracting%20Column%20Names%201.png)

![Extracting Column Names 2](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Extracting%20Column%20Names%202.png)

### 5. Data Extraction via String Concatenation
Since I only had one text column available, I couldn't simply request `SELECT username, password`. Instead, I used the `||` concatenation operator to merge them into a single string, separated by a tilde (`~`) to make the credentials easy to read.

I injected the final payload:
`Pets'+UNION+SELECT+NULL,+username||'~'||password+FROM+users--`

The payload executed successfully, dumping the concatenated credentials into the HTTP response. Scanning the output, I found the administrator's string: `administrator~jx31czlxjkl7zqm3q4bt`. I easily extracted the password `jx31czlxjkl7zqm3q4bt`.

![Concatenation Data Dump](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Concatenation%20Data%20Dump.png)

### 6. Authentication and Verification
Armed with the extracted password, I navigated to the `/login` endpoint.

![Login Page](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Login%20Page.png)

I logged in using `administrator` and the extracted password. The application authenticated the session, redirected me to the "My Account" page, and triggered the "Congratulations, you solved the lab!" banner.

![Solved Lab Banner](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column/Solved%20Lab%20%20Banner.png)

## Remediation
To prevent this vulnerability entirely, the application must use parameterized queries (prepared statements) for all database interactions. Parameterization ensures that user input is treated strictly as data literals by the database driver, stripping its ability to alter the underlying query structure, execute UNION statements, or perform arbitrary string concatenations.