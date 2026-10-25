# PortSwigger Lab: SQL Injection UNION Attack, Finding a Column Containing Text

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective
The objective of this lab is to execute a SQL injection UNION attack to determine the number of columns returned by the query, identify which of those columns can accept text data, and retrieve a specific random string provided by the lab instructions (in this case, `'isiDps'`).

## The Vulnerability Concept
When performing a `UNION` attack, two strict rules apply:
1. The injected query must return the exact same number of columns as the original query.
2. The data types in each column must be compatible between the original and injected queries.

If you attempt to inject a string literal (like `'abc'`) into a column that expects an integer, the database will throw an error. By systematically injecting a string into each column one by one while keeping the others as `NULL`, an attacker can map out the data types of the underlying table and identify where sensitive text data (like usernames or passwords) can be extracted.

## Step-by-Step Exploitation

### 1. Reconnaissance & Interception
To start, I accessed the lab interface and checked the specific requirements. The lab provided a target string to retrieve: `'isiDps'`.

![Lab Overview](images/SQL%20Injection%20UNION%20Attack,%20Finding%20a%20Column%20Containing%20Text/Lab%20Overview.png)

I navigated to the storefront and clicked on the **Food & Drink** category to apply a filter.

![Target String Identified](images/SQL%20Injection%20UNION%20Attack,%20Finding%20a%20Column%20Containing%20Text/Target%20String%20Identified.png)

![Category Filter Selection](images/SQL%20Injection%20UNION%20Attack,%20Finding%20a%20Column%20Containing%20Text/Category%20Filter%20Selection.png)

Using Burp Suite, I monitored the HTTP history to locate the `GET /filter?category=Food+%26+Drink` request. 

![Proxy History](images/SQL%20Injection%20UNION%20Attack,%20Finding%20a%20Column%20Containing%20Text/Proxy%20History.png)

I sent this request to Burp Repeater for testing.

![Burp Repeater Interface](images/SQL%20Injection%20UNION%20Attack,%20Finding%20a%20Column%20Containing%20Text/Burp%20Repeater%20Interface.png)

### 2. Determining the Column Count
Before finding the string column, I needed to determine the total number of columns using the `ORDER BY` technique:

*   **Test 1:** Injecting `'+order+by+1--` returned `HTTP/2 200 OK`.

![Order By 1](images/SQL%20Injection%20UNION%20Attack,%20Finding%20a%20Column%20Containing%20Text/Order%20By%201.png)

*   **Test 2:** Injecting `'+order+by+2--` returned `HTTP/2 200 OK`.

![Order By 2](images/SQL%20Injection%20UNION%20Attack,%20Finding%20a%20Column%20Containing%20Text/Order%20By%202.png)

*   **Test 3:** Injecting `'+order+by+3--` returned `HTTP/2 200 OK`.

![Order By 3](images/SQL%20Injection%20UNION%20Attack,%20Finding%20a%20Column%20Containing%20Text/Order%20By%203.png)

*   **Test 4:** Injecting `'+order+by+4--` triggered an `HTTP/2 500 Internal Server Error`.

![Order By 4 Error](images/SQL%20Injection%20UNION%20Attack,%20Finding%20a%20Column%20Containing%20Text/Order%20By%204%20Error.png)

Because column index `4` caused an error, I confirmed the original query returns exactly **3 columns**.

### 3. Finding the String-Compatible Column
With the column count confirmed as 3, I tested each column sequentially to see which one could hold string data by injecting `'abc'` alongside `NULL` values.

*   **Testing Column 1:** I injected `'+UNION+SELECT+'abc',+NULL,+NULL--`. The server returned a `500 Internal Server Error`, indicating the first column does not accept strings.

![Testing Column 1](images/SQL%20Injection%20UNION%20Attack,%20Finding%20a%20Column%20Containing%20Text/Testing%20Column%201.png)

*   **Testing Column 2:** I moved the string to the second position and injected `'+UNION+SELECT+NULL,+'abc',+NULL--`. The server returned a `200 OK`, confirming the second column accepts string data.

![Testing Column 2](images/SQL%20Injection%20UNION%20Attack,%20Finding%20a%20Column%20Containing%20Text/Testing%20Column%202.png)

### 4. Injecting the Target String
Now that I knew the second column was the correct target, I swapped out my `'abc'` test string for the specific string required to solve the lab: `'isiDps'`.

The final payload was:
`'+UNION+SELECT+NULL,+'isiDps',+NULL--`

Executing this request successfully reflected the target string into the HTML response.

![Injecting Target String](images/SQL%20Injection%20UNION%20Attack,%20Finding%20a%20Column%20Containing%20Text/Injecting%20Target%20String.png)

### 5. Verification
Rendering this successful response in the browser triggered the "Congratulations, you solved the lab!" banner, confirming the completion of the exercise.

![Solved Lab Banner](images/SQL%20Injection%20UNION%20Attack,%20Finding%20a%20Column%20Containing%20Text/Solved%20Lab%20Banner.png)

## Remediation
To prevent UNION-based SQL injections entirely, developers must use parameterized queries (prepared statements) when handling user input. This ensures that user-supplied data in the `category` parameter is treated safely as a string literal and cannot modify the structure of the underlying SQL query to append arbitrary `UNION` operations.