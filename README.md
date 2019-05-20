# Passed Ball

Passed Ball is a library for generating Authentication headers for the authentication
schemes used in response to a WWW-Authenticate header in an HTTP response. Typically,
when a browser requests a protected resource, the server responds with a `401 - Unauthorized`
response, usually with a `WWW-Authenticate` header that indicates the type of authentiction
required to access the resource. When a browser prompts the user for credentials after
receiving the 401 response, it resends the request with the appropriate `Authorization`
header for the requested authentication type.

When writing automated tests for websites that use browser-based authentication using
tools like [Selenium](https://www.seleniumhq.org/), the user often hits a wall when
presented with the browser's authentication dialogs, having to resort to hacks that
are no longer supported by browsers (like embedding the user name and password in the
URL, which all modern browsers disallow), or by using a tool that is not cross-platform
(like Auto-It!) which reduces the usefulness of a cross-platform browser automation
library.

Fortunately, by using a web proxy, one is able to intercept and modify the HTTP requests
and responses before the browser prompts cause havoc in the automated test. The trick
is knowing how to format the data in the Authentication header of the HTTP request to the
web server. Authentication schemes like basic authentication are relatively easy; more
secure authentication schemes like digest or NTLM authentication are not. This library
is intended to help create the correct authentication header values.

### Supported Authentication Schemes
* Basic
* Digest
* NTLM

More authentication schemes can be added if there is appropriate demand.

### A Note about Pull Requests and Issues
Contributions are always welcome in the form of Pull Requests (PRs). Feel free to submit
them as needed, and they will be reviewed as soon as possible. Regarding issue reports,
if the issue is a feature or enhancement request, do submit it as a new issue report here
in the issue tracker for discussion. In the issue report description, please indicate
clearly that it is a request for new functionality, and the issue report will be tagged
appropriately.

Bug reports are required to have an accompanying PR with a failing test that demonstrates
the bug. Please note that the PR is not required to fix the bug; it must merely include a
failing test that reproduces the issue when using the current code base at the time of
submission. Bug reports without a link to an accompanying PR with a failing test will have
one comment asking for the failing test PR. If the PR is not supplied within one week of
the request for the PR, the bug report will be summarily closed. This policy is not intended
to be harsh, but is intended to prevent the common case of being unable to reproduce issues
reported as bugs.

### Why "Passed Ball?"
I am a fan of the sport of [baseball](https://en.wikipedia.org/wiki/Baseball). My experience
with the game is related to my family, and comes to me from my late grandfather. He played
the game at a semi-professional level in the 1940s, and he and I bonded over it when I was
a child. Because of my love for the game, I've taken to naming small, one-off utilities
after various terms in the game. In baseball, a "passed ball" is when a catcher fails to
properly field a fieldable pitch thrown by the pitcher, as opposed to a "wild pitch"
where the catcher fails to field a pitch that was not typically fieldable. The former is
a mistake by the catcher; the latter a mistake by the pitcher. There is nothing more or
less significant to the name than it's simply a term from a sport I enjoy.
