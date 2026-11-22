# PortSwigger Lab: DOM XSS in `document.write` Sink Using Source `location.search`

**Difficulty:** Apprentice
**Target:** PortSwigger Web Security Academy

## Objective

The goal of this lab is to exploit a DOM-based cross-site scripting (DOM XSS) vulnerability in the search query tracking functionality. The client-side JavaScript reads data from `location.search` (the source) and passes it directly into `document.write` (the sink). To solve the lab, we must break out of the surrounding HTML context and execute the `alert` function.

## The Vulnerability Concept

DOM-based Cross-Site Scripting (DOM XSS) occurs when an application contains client-side JavaScript that processes data from an untrusted **source** (such as `window.location.search`, `location.hash`, or `document.referrer`) in an unsafe way, usually by writing the data back into the Document Object Model (DOM) via a dangerous **sink** (such as `document.write()`, `innerHTML`, or `eval()`).

In this lab, the page includes a client-side tracking script that extracts the `search` parameter from `window.location.search` and concatenates it directly into an `<img>` tag string passed to `document.write()`:

```javascript
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if(query) {
    trackSearch(query);
}
```

Because `URLSearchParams.get('search')` automatically URL-decodes the query parameter and `trackSearch()` does not HTML-encode or sanitize `query` before calling `document.write()`, an attacker can inject `">` to prematurely close the `src` attribute and the `<img>` element, allowing arbitrary HTML and `<script>` tags to be written directly into the document.

## Step-by-Step Exploitation

### 1. Reconnaissance

I started by reviewing the lab description, which notes that the search query tracking functionality uses the JavaScript `document.write` sink with data originating from `location.search`.

![Lab Description](images/DOM%20XSS%20in%20`document.write`%20Sink%20Using%20Source%20`location.search`/Lab%20Description.png)

Next, I launched the lab environment and navigated to the main blog homepage, which contains the search bar (`Search the blog...`).

![Blog Home Page](images/DOM%20XSS%20in%20`document.write`%20Sink%20Using%20Source%20`location.search`/Blog%20Home%20Page.png)

To observe how the application processes search queries in the DOM, I entered the test string `test` into the search input box and clicked **Search**.

![Searching for Test String](images/DOM%20XSS%20in%20`document.write`%20Sink%20Using%20Source%20`location.search`/Searching%20for%20Test%20String.png)

### 2. Inspecting the DOM & Identifying Source and Sink

Once the search results page loaded (`/?search=test`), I opened the browser's Developer Tools (**Inspector** tab) and searched the DOM for `test`.

Inspecting the page structure revealed two places where `test` was used:
1. Inside the main `<h1>` heading (`1 search results for 'test'`), where special characters are safely HTML-encoded by the server.
2. Inside a client-side `<script>` block that defines `trackSearch(query)` and dynamically writes an `<img>` element into the DOM:
   `<img src="/resources/images/tracker.gif?searchTerms=test">`

![Inspecting DOM and Vulnerable Script](images/DOM%20XSS%20in%20`document.write`%20Sink%20Using%20Source%20`location.search`/Inspecting%20DOM%20and%20Vulnerable%20Script.png)

### 3. Crafting and Injecting the DOM XSS Payload

Because our input is placed directly inside the double-quoted `src` attribute of the `<img>` tag via `document.write()`, we need to break out of the double quotes and close the `<img>` tag before injecting our `<script>` block:

```html
"><script>alert('hello world!')</script>
```

**How the payload works:**
* `"` closes the opening double quote of `src="/resources/images/tracker.gif?searchTerms=`.
* `>` closes the `<img ...>` tag prematurely.
* `<script>alert('hello world!')</script>` injects a new script element that `document.write()` parses and executes immediately.

I entered `"><script>alert('hello world!')</script>` into the search box and clicked **Search**.

![Entering DOM XSS Payload into Search Box](images/DOM%20XSS%20in%20`document.write`%20Sink%20Using%20Source%20`location.search`/Entering%20DOM%20XSS%20Payload%20into%20Search%20Box.png)

### 4. Execution and Verification

Upon submitting the search form, the browser navigated to `/?search="><script>alert('hello+world!')<%2Fscript>`. Notice how the main heading safely HTML-encoded the input (`0 search results for '"><script>alert('hello world!')</script>'`), but when the client-side `trackSearch()` script executed `document.write()`, it wrote our raw `<script>` tag into the DOM and triggered the `hello world!` alert box.

![DOM XSS Alert Triggered](images/DOM%20XSS%20in%20`document.write`%20Sink%20Using%20Source%20`location.search`/DOM%20XSS%20Alert%20Triggered.png)

After clicking **OK** to dismiss the alert dialog, the page finished rendering with the **"Congratulations, you solved the lab!"** banner, and the **Inspector** tab clearly showed our broken-out `<img src="/resources/images/tracker.gif?searchTerms=">` tag followed immediately by `<script>alert('hello world!')</script>`.

![Lab Solved and DOM Inspector Verification](images/DOM%20XSS%20in%20`document.write`%20Sink%20Using%20Source%20`location.search`/Lab%20Solved%20and%20DOM%20Inspector%20Verification.png)

## Remediation

To prevent DOM-based XSS vulnerabilities when working with URL parameters and DOM manipulation:

1. **Avoid Dangerous Sinks like `document.write()`:** Instead of constructing raw HTML strings with `document.write()`, create DOM elements programmatically using safe DOM APIs such as `document.createElement('img')` and set attributes via `element.setAttribute('src', ...)` or `img.src = ...`.
2. **Encode Data for the Target Context:** When embedding untrusted query values into a URL query string (like `tracker.gif?searchTerms=`), apply `encodeURIComponent(query)` so special characters like `"` and `>` are percent-encoded (`%22` and `%3E`) and cannot break out of the attribute or HTML tag.