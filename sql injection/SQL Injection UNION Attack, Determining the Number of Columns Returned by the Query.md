# PortSwigger Lab: SQL Injection UNION Attack, Determining the Number of Columns Returned by the Query

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective
The objective of this lab is to determine the number of columns returned by the application's original query by performing a SQL injection UNION attack that returns an additional row containing null values.

## The Vulnerability Concept
When performing a `UNION` attack, the injected query must return the exact same number of columns as the original query, and the data types in each column must be compatible. Before extracting any data from external tables, an attacker must systematically figure out how many columns the original `SELECT` statement contains. This is typically done using either an `ORDER BY` clause or by injecting successive `NULL` values.

## Step-by-Step Exploitation

### 1. Reconnaissance & Interception
To start, I accessed the lab interface and reviewed the lab instructions.

![Lab Overview](images/SQL%20Injection%20UNION%20Attack,%20Determining%20the%20Number%20of%20Columns%20Returned%20by%20the%20Query/Lab%20Overview.png)

Navigating to the main storefront revealed the e-commerce category filtering functionality.

![Storefront Home](images/SQL%20Injection%20UNION%20Attack,%20Determining%20the%20Number%20of%20Columns%20Returned%20by%20the%20Query/StoreFront%20Home.png)

I clicked on the **Lifestyle** category filter to trigger a request to the vulnerable endpoint.

![Category Filter Selection](images/SQL%20Injection%20UNION%20Attack,%20Determining%20the%20Number%20of%20Columns%20Returned%20by%20the%20Query/Category%20Filter%20Selection.png)

Using Burp Suite, I monitored the **HTTP history** tab to examine the incoming and outgoing traffic.

![Proxy History](images/SQL%20Injection%20UNION%20Attack,%20Determining%20the%20Number%20of%20Columns%20Returned%20by%20the%20Query/Proxy%20History.png)

I located the target `GET /filter?category=Lifestyle` request and sent it to **Burp Repeater** to begin testing.

![Burp Repeater Interface](images/SQL%20Injection%20UNION%20Attack,%20Determining%20the%20Number%20of%20Columns%20Returned%20by%20the%20Query/Burp%20Repeater%20Interface.png)

### 2. Determining Column Count via `ORDER BY`
The first method to find the column count is using the `ORDER BY` clause, which sorts the result set by the specified column index. If an index greater than the actual number of columns is provided, the database throws an error.

*   **Test 1:** Injecting `'+order+by+1--` returned an `HTTP/2 200 OK`.

![Order By 1](images/SQL%20Injection%20UNION%20Attack,%20Determining%20the%20Number%20of%20Columns%20Returned%20by%20the%20Query/Order%20By%201.png)

*   **Test 2:** Injecting `'+order+by+2--` also returned an `HTTP/2 200 OK`.

![Order By 2](images/SQL%20Injection%20UNION%20Attack,%20Determining%20the%20Number%20of%20Columns%20Returned%20by%20the%20Query/Order%20By%202.png)

*   **Test 3:** Injecting `'+order+by+3--` returned an `HTTP/2 200 OK`.

![Order By 3](images/SQL%20Injection%20UNION%20Attack,%20Determining%20the%20Number%20of%20Columns%20Returned%20by%20the%20Query/Order%20By%203.png)

*   **Test 4:** Injecting `'+order+by+4--` triggered an `HTTP/2 500 Internal Server Error`.

![Order By 4 Error](images/SQL%20Injection%20UNION%20Attack,%20Determining%20the%20Number%20of%20Columns%20Returned%20by%20the%20Query/Order%20By%204%20Error.png)

Since column index `4` caused a database error while column `3` succeeded, I confirmed that the original query returns exactly **3 columns**.

### 3. Verifying with `UNION SELECT NULL`
To confirm the column count and successfully solve the lab, I crafted a `UNION` payload with three `NULL` values:
`'+UNION+SELECT+NULL,+NULL,+NULL--`

Injecting this into the category parameter resulted in a successful `HTTP/2 200 OK` response, appending an extra row of null values to the application output.

![Union Select Null Success](images/SQL%20Injection%20UNION%20Attack,%20Determining%20the%20Number%20of%20Columns%20Returned%20by%20the%20Query/Union%20Select%20Null%20Success.png)

### 4. Verification
Loading the crafted payload in the browser successfully rendered the page without errors and triggered the "Congratulations, you solved the lab!" banner.

![Solved Lab Banner](images/SQL%20Injection%20UNION%20Attack,%20Determining%20the%20Number%20of%20Columns%20Returned%20by%20the%20Query/Solved%20Lab%20Banner.png)

## Remediation
To fix this vulnerability, parameterized queries (prepared statements) must be used for handling user input within database queries, ensuring that user-controlled values cannot manipulate the query structure or append unauthorized `UNION` operations.