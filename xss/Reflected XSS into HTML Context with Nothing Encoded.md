# PortSwigger Lab: Reflected XSS into HTML Context with Nothing Encoded

**Difficulty:** Apprentice
**Target:** PortSwigger Web Security Academy

## Objective

The goal of this lab is to exploit a simple reflected cross-site scripting (XSS) vulnerability in the blog's search functionality by injecting a payload that executes the `alert` function in the browser.

## The Vulnerability Concept

Reflected Cross-Site Scripting (XSS) occurs when an application receives user-supplied data in an HTTP request and includes that data within the immediate HTTP response in an unsafe manner, without proper validation or output encoding. 

When user input is reflected directly into the HTML body context with nothing encoded (such as `<` and `>` characters), an attacker can inject `<script>` tags directly into the parameter. When a victim's browser parses the returned HTML, it treats the injected `<script>` block as legitimate JavaScript code and executes it within the context of the user's session.

## Step-by-Step Exploitation

### 1. Reconnaissance

I started by reviewing the lab description, which notes that the search feature on the blog is vulnerable to reflected XSS and requires calling the `alert` function to solve the lab.

![Lab Description](images/Reflected%20XSS%20into%20HTML%20Context%20with%20Nothing%20Encoded/Lab%20Description.png)

Next, I launched the lab environment and navigated to the main blog page, which features a search input bar (`Search the blog...`).

![Blog Home Page](images/Reflected%20XSS%20into%20HTML%20Context%20with%20Nothing%20Encoded/Blog%20Home%20Page.png)

### 2. Crafting and Injecting the XSS Payload

Because the application reflects the search query directly into the HTML response (e.g., `<h1>0 search results for 'USER_INPUT'</h1>`) without encoding HTML special characters, we can inject a standard `<script>` payload directly into the search bar:

```html
<script>alert('hello world')</script>
```

I typed `<script>alert('hello world')</script>` into the search input box and clicked **Search**.

![Entering XSS Payload into Search Bar](images/Reflected%20XSS%20into%20HTML%20Context%20with%20Nothing%20Encoded/Entering%20XSS%20Payload%20into%20Search%20Bar.png)

### 3. Execution and Verification

Upon submitting the search query, the browser navigated to `/?search=<script>alert('hello+world')<%2Fscript>`. The backend reflected our raw `<script>` tags directly into the HTML document, causing the browser to immediately execute the JavaScript and pop up the `hello world` alert box.

![Alert Box Triggered](images/Reflected%20XSS%20into%20HTML%20Context%20with%20Nothing%20Encoded/Alert%20Box%20Triggered.png)

After dismissing the alert dialog by clicking **OK**, the page finished rendering and displayed the **"Congratulations, you solved the lab!"** banner at the top of the screen.

![Lab Solved Confirmation](images/Reflected%20XSS%20into%20HTML%20Context%20with%20Nothing%20Encoded/Lab%20Solved%20Confirmation.png)

## Remediation

To prevent reflected XSS vulnerabilities when inserting user-controlled data into an HTML context, developers must implement **context-aware output encoding** before rendering the response:

1. **HTML Entity Encoding:** Convert potentially dangerous characters into their corresponding safe HTML entities so the browser treats them strictly as text content rather than executable markup:
   * `<` $\rightarrow$ `&lt;`
   * `>` $\rightarrow$ `&gt;`
   * `"` $\rightarrow$ `&quot;`
   * `'` $\rightarrow$ `&#x27;`
   * `&` $\rightarrow$ `&amp;`
2. **Use Modern Templating Engines:** Utilize modern web frameworks and templating engines (such as React, Angular, or Twig) that automatically HTML-encode variables by default.
3. **Implement a Content Security Policy (CSP):** Deploy a strict `Content-Security-Policy` header (such as disallowing `unsafe-inline` scripts) as a defense-in-depth measure to prevent unauthorized inline scripts from executing even if an injection point exists.