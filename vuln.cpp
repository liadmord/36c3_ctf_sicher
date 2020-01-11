#include <iostream>
#include <sstream>
#include <thread>
#include <regex>
#include <filesystem>
#include <unistd.h>
#include <sys/fcntl.h>

using namespace std::literals::string_literals;

std::optional<std::string> b64decode(std::string s)
{
    static const std::string alph("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");
    std::string r;
    if (s.length() % 4) return {};
    size_t eq = s.find_first_of('=');
    eq = eq == std::string::npos ? 0 : s.length() - eq;
    while (!s.empty()) {
        uint32_t t = 0;
        for (int i = 0; i < 4; ++i) t |= alph.find_first_of(s[i]) % 64 << (18 - 6*i);
        for (int i = 0; i < 3; ++i) r.push_back(t >> (16 - 8*i));
        s.erase(0, 4);
    }
    r.erase(r.length() - eq);
    return r;
}

static std::string rtrim(std::string s)
{
    auto f = [](int c) { return !std::isspace(c); };
    s.erase(std::find_if(s.rbegin(), s.rend(), f).base(), s.end());
    return s;
}

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

static bool check_password(std::string const& theirs)
{
    return theirs == rtrim(reader("password.txt").get());
}

static std::optional<std::string> canonicalize(std::string const& s)
{
    try {
        return std::filesystem::canonical(std::filesystem::path(s)).string();
    }
    catch (std::filesystem::filesystem_error const& e) {
        return {};
    }
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

struct response_info
{
    unsigned status;
    std::string message;
    std::vector<std::string> headers;
    std::string content;
};

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
