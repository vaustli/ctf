## Solution
[Two windows][1] coordinate to capture the flag:
the parent window submits the flag hence won't go back,
after it opens a child window with `window.open()`.
The child one sets a listener in around 200 seconds,
reporting the flag to our hook, which is retrieved by
`window.opener.document.documentElement.outerHTML`.

[This blog][2] uses the `target` attribute to pin the form into a window,
through which the content (flag) can be accessed.


[1]: https://hackmd.io/@lamchcl/r1zQkbvpj#webcalifornia-state-police
[2]: https://blog.jaquiez.dev/Blog/LACTF2023/#CSP
