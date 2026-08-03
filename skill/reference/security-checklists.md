# Language-Specific Security Checklists

Load this file only when running security reviewers. Reviewers should apply the
checklist for the language(s) actually present in their assigned file list and
ignore the rest.

## Ruby/Rails
- [ ] Mass assignment protection (strong parameters)
- [ ] SQL injection via `find_by_sql`, `where` with interpolation
- [ ] Command injection via `system`, `exec`, backticks, `%x{}`
- [ ] Unsafe deserialization (`Marshal.load`, `YAML.load`)
- [ ] `eval`, `instance_eval`, `class_eval` with user input
- [ ] `constantize`, `safe_constantize` with untrusted input
- [ ] `send`, `public_send` with user-controlled method names
- [ ] `render inline:` or `render text:` with user input
- [ ] `redirect_to` with user-controlled URLs (open redirect)
- [ ] File uploads (path traversal, content type spoofing, size limits)
- [ ] CSRF token verification disabled
- [ ] Session security (httponly, secure, same_site)
- [ ] Brakeman scan results reviewed
- [ ] Secret key base protection
- [ ] Raw SQL in ActiveRecord (Arel abuse)

## Python
- [ ] `eval`, `exec`, `compile` with user input
- [ ] `pickle.loads` with untrusted data
- [ ] `yaml.load` (use `yaml.safe_load`)
- [ ] `subprocess` with `shell=True`
- [ ] SQL string formatting (f-strings, % formatting)
- [ ] `__import__`, `importlib` with dynamic paths
- [ ] `marshal`, `shelve` with untrusted data
- [ ] Template injection (Jinja2, Django templates)
- [ ] `xml.etree`, `xml.dom` with external entities
- [ ] Django mass assignment, CSRF settings
- [ ] Flask `SECRET_KEY` management
- [ ] Path traversal in file handling
- [ ] Deserialization of untrusted JSON with custom decoders

## JavaScript/TypeScript
- [ ] `eval()`, `Function()`, `setTimeout`/`setInterval` with strings
- [ ] `innerHTML`, `outerHTML` with user input
- [ ] `document.write` usage
- [ ] Prototype pollution (`__proto__`, `constructor`)
- [ ] `require()` with dynamic paths
- [ ] `child_process.exec` with user input
- [ ] NoSQL injection (MongoDB query objects)
- [ ] JWT `none` algorithm, weak secrets
- [ ] `Math.random()` for security tokens (use `crypto.randomBytes`)
- [ ] `JSON.parse` with reviver abuse
- [ ] DOM-based XSS (location.hash, URL parameters)
- [ ] CORS misconfiguration (`*`, credentials true)
- [ ] CSP bypass opportunities
- [ ] npm package vulnerabilities (`npm audit`)
- [ ] `Buffer` constructor deprecation (use `Buffer.alloc`, `Buffer.from`)

## Java
- [ ] `ObjectInputStream.readObject` (deserialization)
- [ ] `Runtime.exec`, `ProcessBuilder` with user input
- [ ] SQL concatenation (PreparedStatement?)
- [ ] `ScriptEngine.eval`, `javax.script` usage
- [ ] XXE in XML parsing (DocumentBuilderFactory, SAXParserFactory)
- [ ] Reflection abuse (`setAccessible`, `invoke`)
- [ ] JNI/native code usage
- [ ] `Class.forName` with dynamic names
- [ ] Spring expression language injection
- [ ] Log4j/Logback configuration (JNDI, serialization)
- [ ] JWT library vulnerabilities
- [ ] Path traversal in file operations
- [ ] Mass assignment in Spring MVC
- [ ] Insecure random (`java.util.Random` vs `SecureRandom`)

## Go
- [ ] `unsafe` package usage
- [ ] `cgo` usage and C library vulnerabilities
- [ ] SQL string concatenation (parameterized queries?)
- [ ] `os/exec` with user input
- [ ] `text/template`, `html/template` with untrusted input
- [ ] `filepath.Join` with `..` components
- [ ] Integer overflow (bounds checking)
- [ ] `json.Unmarshal` to `interface{}` with type confusion
- [ ] `reflect` package abuse
- [ ] Race conditions (goroutine safety)
- [ ] `crypto/rand` vs `math/rand` for security
- [ ] `pprof` exposed in production
- [ ] `net/http` timeout configurations
- [ ] `x/net/html` parsing with untrusted input
