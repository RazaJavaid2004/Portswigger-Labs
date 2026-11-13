# PortSwigger Lab: Stored XSS into HTML Context with Nothing Encoded

**Difficulty:** Apprentice
**Target:** PortSwigger Web Security Academy

## Objective

The goal of this lab is to exploit a stored cross-site scripting (XSS) vulnerability in the blog post comment functionality by submitting a comment that executes the `alert` function whenever the blog post is viewed.

## The Vulnerability Concept

Stored (or Persistent) Cross-Site Scripting (XSS) occurs when an application receives user-supplied input, stores it on the backend (typically in a database), and later embeds that data into HTTP responses served to other users without proper output encoding or sanitization.

Unlike reflected XSS—which requires tricking a victim into clicking a specially crafted link—stored XSS automatically executes in the browser of *every* user who visits the affected page (such as a blog post comment section or user profile). When the comment body is rendered directly into the HTML context with nothing encoded, an attacker can inject raw `<script>` tags that permanently execute JavaScript in the context of every visitor's session.

## Step-by-Step Exploitation

### 1. Reconnaissance

I started by reviewing the lab description, which notes that the blog's comment functionality contains a stored XSS vulnerability and requires calling the `alert` function when the blog post is viewed.

![Lab Description](images/Stored%20XSS%20into%20HTML%20Context%20with%20Nothing%20Encoded/Lab%20Description.png)

Next, I launched the lab environment and navigated to the main blog homepage, which lists several blog posts.

![Blog Home Page](images/Stored%20XSS%20into%20HTML%20Context%20with%20Nothing%20Encoded/Blog%20Home%20Page.png)

I clicked on the first blog post titled **"Trying To Save The World"** (`/post?postId=6`) to inspect the post content and its comment section.

![Viewing Blog Post](images/Stored%20XSS%20into%20HTML%20Context%20with%20Nothing%20Encoded/Viewing%20Blog%20Post.png)

### 2. Crafting and Submitting the Stored XSS Payload

Scrolling down to the **Leave a comment** section, I observed fields for `Comment`, `Name`, `Email`, and `Website`. Because the application renders user comments directly into the HTML document without encoding special characters, I entered the following JavaScript payload into the `Comment` box:

```html
<script>alert('hello world')</script>
```

I filled in dummy values for the remaining required fields (`Name: test`, `Email: test@test.com`, `Website: http://test.com`) and clicked **Post Comment**.

![Submitting XSS Payload in Comment Form](images/Stored%20XSS%20into%20HTML%20Context%20with%20Nothing%20Encoded/Submitting%20XSS%20Payload%20in%20Comment%20Form.png)

### 3. Execution and Verification

Upon submitting the comment, the application stored the payload in the backend database, redirecting to the comment confirmation page (`/post/comment/confirmation?postId=6`) and immediately displaying the **"Congratulations, you solved the lab!"** banner.

![Comment Confirmation and Lab Solved](images/Stored%20XSS%20into%20HTML%20Context%20with%20Nothing%20Encoded/Comment%20Confirmation%20and%20Lab%20Solved.png)

To verify the persistent execution of the payload, I clicked **< Back to blog** to reload `/post?postId=6`. As soon as the browser parsed the stored comment on the blog post page, our injected `<script>` tag executed and triggered the `hello world` alert box.

![Stored XSS Alert Triggered on Blog Post](images/Stored%20XSS%20into%20HTML%20Context%20with%20Nothing%20Encoded/Stored%20XSS%20Alert%20Triggered%20on%20Blog%20Post.png)

Dismissing the alert box by clicking **OK** allowed the rest of the blog post page (`postId=6`) to finish rendering with the solved lab status confirmed.

![Blog Post Rendered After Alert](images/Stored%20XSS%20into%20HTML%20Context%20with%20Nothing%20Encoded/Blog%20Post%20Rendered%20After%20Alert.png)

## Remediation

To prevent stored XSS vulnerabilities, developers must implement defense-in-depth across both input handling and output rendering:

1. **Context-Aware Output Encoding:** Always HTML-encode user-supplied data right before rendering it into an HTML document context (converting `<` to `&lt;`, `>` to `&gt;`, `"` to `&quot;`, `'` to `&#x27;`, and `&` to `&amp;`). This ensures the browser displays the comment strictly as plain text rather than interpreting it as executable HTML/JavaScript.
2. **Input Sanitization (When HTML is Allowed):** If the application intentionally allows users to submit rich text or limited HTML formatting, sanitize the input using a strict, actively maintained allowlist HTML sanitizer (such as DOMPurify) before storing or rendering it.
3. **Content Security Policy (CSP):** Implement a robust `Content-Security-Policy` header that disables inline script execution (`script-src 'self'`), mitigating the impact of any unencoded markup injection.
