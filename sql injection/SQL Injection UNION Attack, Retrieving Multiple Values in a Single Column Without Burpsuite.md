# PortSwigger Lab: SQL Injection UNION Attack, Retrieving Multiple Values in a Single Column

**Difficulty:** Practitioner
**Target:** PortSwigger Web Security Academy

## Objective
The objective of this lab is to exploit a SQL injection vulnerability in the product category filter. The query only returns a single column that accepts string data, so we must use string concatenation to retrieve both the usernames and passwords from the `users` table simultaneously, and then log in as the `administrator`.

*Note: While I often use **Burp Suite** (specifically the Repeater tool) to rapidly iterate through payloads in the HTTP request backend, this write-up demonstrates how to perform the entire attack manually directly within the browser's URL bar. Both methods are essential skills for a security analyst.*

## Step-by-Step Exploitation

### 1. Reconnaissance
I started by reviewing the lab instructions, which established our goal: extract the contents of the `users` table to compromise the administrator account.

![Lab Description](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column%20Without%20Burpsuite/Lab%20Description.png)

I navigated to the main storefront to interact with the application and understand its routing.

![Storefront Home](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column%20Without%20Burpsuite/Storefront%20Home.png)

Clicking on the **Clothing, shoes and accessories** category applied a filter, altering the URL to include the query parameter: `?category=Clothing%2c+shoes+and+accessories`. This parameter is our injection vector.

![Category Selection](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column%20Without%20Burpsuite/Category%20Selection.png)

### 2. Determining the Column Count
To structure my UNION attack, I first needed to figure out how many columns the backend query was returning. I appended `ORDER BY` payloads directly into the browser's address bar:

*   Injecting `+order+by+1--` loaded the page successfully.
![Order By 1](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column%20Without%20Burpsuite/Order%20By%201.png)

*   Injecting `+order+by+2--` also loaded the page successfully.
![Order By 2](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column%20Without%20Burpsuite/Order%20By%202.png)

*   Injecting `+order+by+3--` resulted in an "Internal Server Error".
![Order By 3 Error](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column%20Without%20Burpsuite/Order%20By%203%20Error.png)

The error at index 3 confirmed that the backend query returns exactly **2 columns**.

### 3. Finding the Text-Compatible Column
Next, I needed to determine which of these two columns could hold string data, as we need a text column to dump our credentials. 

I tested the first column by injecting `'+UNION+SELECT+'abc',+NULL--`. This resulted in an Internal Server Error, indicating the first column does not accept strings.

![Text Column Test 1 Failure](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column%20Without%20Burpsuite/Text%20Column%20Test%201%20Failure.png)

I then moved the string to the second column by injecting `'+UNION+SELECT+NULL,+'abc'--`. The page loaded successfully and rendered my `'abc'` string on the screen, confirming the **second column** accepts text data.

![Text Column Test 2 Success](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column%20Without%20Burpsuite/Text%20Column%20Test%202%20Success.png)

### 4. Database Enumeration (Schema & Columns)
Even though the lab description hints at the table names, it is best practice to enumerate the database manually to confirm the exact structure. I used my text column to query the `information_schema`.

First, I extracted the table names by injecting:
`'+UNION+SELECT+NULL,table_name+FROM+information_schema.tables--`
Searching the page output, I located the `users` table.

![Enumerating Tables](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column%20Without%20Burpsuite/Enumerating%20Tables.png)

Next, I extracted the columns specifically for the `users` table by injecting:
`'+UNION+SELECT+NULL,column_name+FROM+information_schema.columns+WHERE+table_name='users'--`
Scanning the output, I confirmed the existence of both the `username` and `password` columns.

![Enumerating Username Column](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column%20Without%20Burpsuite/Enumerating%20Username%20Column.png)

![Enumerating Password Column](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column%20Without%20Burpsuite/Enumerating%20Password%20Column.png)

### 5. Data Extraction via String Concatenation
Since I only had *one* text column available but needed *two* pieces of data (username and password), I used string concatenation to merge them. Depending on the SQL dialect, operators like `||`, `+`, or `CONCAT()` are used. 

I injected the final payload using the `||` operator to combine the fields, separated by a space for readability:
`'+UNION+SELECT+NULL,+username||' '||password+FROM+users--`

The payload executed successfully, dumping the concatenated credentials directly onto the storefront page. I located the administrator's entry and copied the password: `jx31cz1xjk17zqm3q4bt`.

![Concatenated Data Extraction](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column%20Without%20Burpsuite/Concatenated%20Data%20Extraction.png)

### 6. Authentication and Verification
Armed with the extracted password, I navigated to the `/login` endpoint.

![Login Page](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column%20Without%20Burpsuite/Login%20Page.png)

I successfully logged in using the `administrator` credentials. The application authenticated the session, redirected me to the "My Account" page, and triggered the "Congratulations, you solved the lab!" banner.

![Lab Solved](images/SQL%20Injection%20UNION%20Attack,%20Retrieving%20Multiple%20Values%20in%20a%20Single%20Column%20Without%20Burpsuite/Solved%20Lab%20Banner.png)

## Remediation
To prevent this vulnerability entirely, the application must use parameterized queries (prepared statements) for all database interactions. Parameterization ensures that user input is treated strictly as data literals by the database driver, stripping its ability to alter the underlying query structure, execute UNION statements, or perform arbitrary string concatenations.