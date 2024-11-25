#!/usr/bin/env python

"""
Copyright (c) 2019-2022 Miroslav Stampar (@stamparm), MIT
See the file 'LICENSE' for copying permission

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
"""

from __future__ import print_function

import base64
import codecs
import difflib
import json
import locale
import optparse
import os
import random
import re
import socket
import ssl
import string
import struct
import sys
import time
import zlib

PY3 = sys.version_info >= (3, 0)
xrange = range
if PY3:

    # requests库实现的话不需要管cookie还有proxy，直接让session管理即可
    # 同样的，也不需要urlopen了，因为session.get()就会打开一个urlopen
    # 从现在开始，我们需要往下去一点一点找到关于install_opener、build_opener、urlopen、CookieJar、ProxyHandler、Request、HTTPCookieProcessor这些东西，将他们改成session操作
    import requests
    from myquote import custom_quote as quote
    from requests.cookies import RequestsCookieJar
    from urllib.parse import urlparse
    session = requests.Session()
    session.cookies = RequestsCookieJar()
    quote = quote
    urlparse = urlparse

NAME = "identYwaf"
VERSION = "first"
BANNER = r"""


 _________                                                          ` __ __ `
 /   _____/__   ________   ______\/____    ____  ___      ___  ____   ______ `|  T  T` __    __   ____  _____ 
 \_____  \|  | | | ____ \_/ __ \_  __ \   l    j|   \    /  _]|    \ |      T`|  |  |`|  T__T  T /    T|   __|
 /----/   \  |-| |  |_> >  ___/|  | \/     |  T |    \  /  [_ |  _  Yl_j  l_j`|  ~  |`|  |  |  |Y  o  ||  l_
/_______  /\____/|   __/ \___  >__|        |  | |  D  YY    _]|  |  |  |  |  `|___  |`|  |  |  ||     ||   _|
        \/       |  |        \/            j  l |     ||   [_ |  |  |  |  |  `|     !` \      / |  |  ||  ] 
                 |__|                     |____jl_____jl_____jl__j__j  l__j  `l____/ `  \_/\_/  l__j__jl__j  (%s)%s""".strip("\n") % (VERSION, "\n")


RAW, TEXT, HTTPCODE, SERVER, TITLE, HTML, URL = xrange(7)
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"
GET, POST = "GET", "POST"
GENERIC_PROTECTION_KEYWORDS = ("rejected", "forbidden", "suspicious", "malicious", "captcha", "invalid", "your ip", "please contact", "terminated", "protected", "unauthorized", "blocked", "protection", "incident", "denied", "detected", "dangerous", "firewall", "fw_block", "unusual activity", "bad request", "request id", "injection", "permission", "not acceptable", "security policy", "security reasons")
GENERIC_PROTECTION_REGEX = r"(?i)\b(%s)\b"
GENERIC_ERROR_MESSAGE_REGEX = r"\b[A-Z][\w, '-]*(protected by|security|unauthorized|detected|attack|error|rejected|allowed|suspicious|automated|blocked|invalid|denied|permission)[\w, '!-]*"
WAF_RECOGNITION_REGEX = None
HEURISTIC_PAYLOAD = "1 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#"  # Reference: https://github.com/sqlmapproject/sqlmap/blob/master/lib/core/settings.py
PAYLOADS = []
SIGNATURES = {}
DATA_JSON = {}
DATA_JSON_FILE = os.path.join(os.path.dirname(__file__), "data.json")
MAX_HELP_OPTION_LENGTH = 18
IS_TTY = sys.stdout.isatty()
IS_WIN = os.name == "nt"
COLORIZE = not IS_WIN and IS_TTY
LEVEL_COLORS = {"o": "\033[00;94m", "x": "\033[00;91m", "!": "\033[00;93m", "i": "\033[00;95m", "=": "\033[00;93m", "+": "\033[00;92m", "-": "\033[00;91m"}
VERIFY_OK_INTERVAL = 5
VERIFY_RETRY_TIMES = 3
MIN_MATCH_PARTIAL = 5
DEFAULTS = {"timeout": 10}
MAX_MATCHES = 5
QUICK_RATIO_THRESHOLD = 0.2
MAX_JS_CHALLENGE_SNAPLEN = 120
ENCODING_TRANSLATIONS = {"windows-874": "iso-8859-11", "utf-8859-1": "utf8", "en_us": "utf8", "macintosh": "iso-8859-1", "euc_tw": "big5_tw", "th": "tis-620", "unicode": "utf8", "utc8": "utf8", "ebcdic": "ebcdic-cp-be", "iso-8859": "iso8859-1", "iso-8859-0": "iso8859-1", "ansi": "ascii", "gbk2312": "gbk", "windows-31j": "cp932", "en": "us"}  # Reference: https://github.com/sqlmapproject/sqlmap/blob/master/lib/request/basic.py
PROXY_TESTING_PAGE = "https://myexternalip.com/raw"

if COLORIZE:
    for _ in re.findall(r"`.+?`", BANNER):
        BANNER = BANNER.replace(_, "\033[01;92m%s\033[00;49m" % _.strip('`'))
    for _ in re.findall(r" [Do] ", BANNER):
        BANNER = BANNER.replace(_, "\033[01;93m%s\033[00;49m" % _.strip('`'))
    BANNER = re.sub(VERSION, r"\033[01;91m%s\033[00;49m" % VERSION, BANNER)
else:
    BANNER = BANNER.replace('`', "")

_ = random.randint(20, 64)
DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; %s; rv:%d.0) Gecko/20100101 Firefox/%d.0" % (NAME, _, _)
HEADERS = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "identity", "Cache-Control": "max-age=0"}

# original = None
# options = None
# intrusive = None
heuristic = None
chained = False
locked_code = None
locked_regex = None
# non_blind = set()
seen = set()
blocked = []
servers = set()
codes = set()
proxies = list()
proxies_index = 0
wafname = None
_exit = sys.exit

class OPTIONS(optparse.OptionParser):
    def __init__(self):
        super(OPTIONS, self).__init__()
        self.proxy_file = None
        self.input_file = None
        self.targets = None
        self.proxy = None
        self.random_agent = None
        self.timeout = None
        self.string = None
        self.code = None
        self.debug = None
        self.fast = None
        self.lock =None
        # self.test_file = None
        # self.wafname_list = {}
        # self.test = False

options = OPTIONS()

def exit(message=None):
    if message:
        print("%s%s" % (message, ' ' * 20))
    _exit(1)

def calc_hash(value, binary=True):
    value = value.encode("utf8") if not isinstance(value, bytes) else value
    result = zlib.crc32(value) & 0xffff
    if binary:
        result = struct.pack(">H", result)
    return result

def single_print(message):
    if message not in seen:
        print(message)
        seen.add(message)

def colorize(message):
    if COLORIZE:
        message = re.sub(r"\[(.)\]", lambda match: "[%s%s\033[00;49m]" % (LEVEL_COLORS[match.group(1)], match.group(1)), message)

        if any(_ in message for _ in ("rejected summary", "challenge detected")):
            for match in re.finditer(r"[^\w]'([^)]+)'" if "rejected summary" in message else r"\('(.+)'\)", message):
                message = message.replace("'%s'" % match.group(1), "'\033[37m%s\033[00;49m'" % match.group(1), 1)
        else:
            for match in re.finditer(r"[^\w]'([^']+)'", message):
                message = message.replace("'%s'" % match.group(1), "'\033[37m%s\033[00;49m'" % match.group(1), 1)
        if "blind match" in message:
            for match in re.finditer(r"\(((\d+)%)\)", message):
                message = message.replace(match.group(1), "\033[%dm%s\033[00;49m" % (92 if int(match.group(2)) >= 95 else (93 if int(match.group(2)) > 80 else 90), match.group(1)))
        if "hardness" in message:
            for match in re.finditer(r"\(((\d+)%)\)", message):
                message = message.replace(match.group(1), "\033[%dm%s\033[00;49m" % (95 if " insane " in message else (91 if " hard " in message else (93 if " moderate " in message else 92)), match.group(1)))
    return message

def load_data():
    global WAF_RECOGNITION_REGEX

    if os.path.isfile(DATA_JSON_FILE):
        with codecs.open(DATA_JSON_FILE, "rb", encoding="utf8") as f:
            DATA_JSON.update(json.load(f))

        WAF_RECOGNITION_REGEX = ""
        for waf in DATA_JSON["wafs"]:
            if DATA_JSON["wafs"][waf]["regex"]:
                WAF_RECOGNITION_REGEX += "%s|" % ("(?P<waf_%s>%s)" % (waf, DATA_JSON["wafs"][waf]["regex"]))
            for signature in DATA_JSON["wafs"][waf]["signatures"]:
                SIGNATURES[signature] = waf
        WAF_RECOGNITION_REGEX = WAF_RECOGNITION_REGEX.strip('|')

        flags = "".join(set(_ for _ in "".join(re.findall(r"\(\?(\w+)\)", WAF_RECOGNITION_REGEX))))
        WAF_RECOGNITION_REGEX = "(?%s)%s" % (flags, re.sub(r"\(\?\w+\)", "", WAF_RECOGNITION_REGEX))  # patch for "DeprecationWarning: Flags not at the start of the expression" in Python3.7
    else:
        exit(colorize("[x] file '%s' is missing" % DATA_JSON_FILE))

def parse_args():
    global options, wafname
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("--delay", default=1 ,dest="delay", type=int, help="Delay (sec) between tests (default: 0)")
    parser.add_option("--timeout",default=5, dest="timeout", type=int, help="Response timeout (sec) (default: 5)")
    parser.add_option("--proxy", dest="proxy", help="HTTP proxy address (e.g. \"http://127.0.0.1:8080\")")
    parser.add_option("--proxy-file", dest="proxy_file", help="Load (rotating) HTTP(s) proxy list from a file")
    parser.add_option("--random-agent", dest="random_agent", action="store_true", help="Use random HTTP User-Agent header value")
    parser.add_option("--code", dest="code", type=int, help="Expected HTTP code in rejected responses")
    parser.add_option("--string", dest="string", help="Expected string in rejected responses")
    parser.add_option("--post", dest="post", action="store_true", help="Use POST body for sending payloads")
    parser.add_option("-a","--allow-redirect", default="True", dest="allow_redirect", action="store_true", help="If set False then requests will not redirect")
    parser.add_option("-i","--input-file", default=None, dest="input_file", help="The targets' file path")
    # parser.add_option("--test-file", default=None, dest="test_file", help="Test tool's accuracy and efficiency")
    parser.add_option("--debug", dest="debug", action="store_true", help=optparse.SUPPRESS_HELP)
    parser.add_option("--fast", dest="fast", action="store_true", help=optparse.SUPPRESS_HELP)
    parser.add_option("--lock", dest="lock", action="store_true", help=optparse.SUPPRESS_HELP)
    def _(self, *args):
        retval = parser.formatter._format_option_strings(*args)
        if len(retval) > MAX_HELP_OPTION_LENGTH:
            retval = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - parser.formatter.indent_increment)) % retval
        return retval
    parser.usage = "python %s <host|url>" % parser.usage
    parser.formatter._format_option_strings = parser.formatter.format_option_strings
    parser.formatter.format_option_strings = type(parser.formatter.format_option_strings)(_, parser)
    for _ in ("-h", "--version"):
        option = parser.get_option(_)
        option.help = option.help.capitalize()
    try:
        options, target_list = parser.parse_args()
        # print(options, target_list)
    except SystemExit:
        raise
    # arg2
    # target_list += ['http://12.69.110.212', 'http://75.119.208.80', 'http://109.234.161.15'] # +['baidu.com', 'bing.com', '81.69.87.198']

    options.targets = []
    if options.input_file == None:
        if len(target_list) > 0:
            # url = sys.argv[-1]
            # if not url.startswith("http"):
            #     url = "http://%s" % url
            # options.url = url
            for target in target_list:
                if not target.startswith("http"):
                    target = "http://" + target
                options.targets.append(target)
        else:
            parser.print_help()
            raise SystemExit


    for key in DEFAULTS:
        if getattr(options, key, None) is None:
            setattr(options, key, DEFAULTS[key])

import csv
def init():
    global options
    os.chdir(os.path.abspath(os.path.dirname(__file__)))

    # Reference: http://blog.mathieu-leplatre.info/python-utf-8-print-fails-when-redirecting-stdout.html
    if not PY3 and not IS_TTY:
        sys.stdout = codecs.getwriter(locale.getpreferredencoding())(sys.stdout)

    print(colorize("[o] initializing handlers..."))

    # Reference: https://stackoverflow.com/a/28052583
    if hasattr(ssl, "_create_unverified_context"):
        ssl._create_default_https_context = ssl._create_unverified_context

    if options.proxy_file:
        if os.path.isfile(options.proxy_file):
            print(colorize("[o] loading proxy list..."))

            with codecs.open(options.proxy_file, "rb", encoding="utf8") as f:
                proxies.extend(re.sub(r"\s.*", "", _.strip()) for _ in f.read().strip().split('\n') if _.startswith("http"))
                random.shuffle(proxies)
        else:
            exit(colorize("[x] file '%s' does not exist" % options.proxy_file))

    if options.input_file:
        if os.path.isfile(options.input_file) and (options.input_file.endswith(".csv") or options.input_file.endswith(".txt")):
            print(colorize("[o] loading target list..."))
            with open(options.input_file, mode="r", encoding="utf-8") as f:
                targets = f.read().split("\n")
                for target in targets:
                    if not target.startswith("http"):
                        target = "http://" + target
                    if target not in options.targets:
                        options.targets.append(target)
        else:
            exit(colorize("[x] file '%s' does not exist" % options.input_file))

    # if options.test_file:
    #     options.test = True
    #     options.wafname_dict = {}
    #     if os.path.isfile(options.test_file) and (options.test_file.endswith(".csv") or options.test_file.endswith(".txt")):
    #         print(colorize("[o] loading test target list..."))
    #         with open(options.test_file, mode='r', encoding='utf-8') as file:
    #             lines = file.readlines()
    #         for line in lines[1:]:  # 从第二行开始
    #             line = line.strip()  # 去掉首尾的空格和换行符
    #             if line:  # 确保行不为空
    #                 wafname, url = line.split(",")  # 假设文件是以逗号分隔的
    #                 options.wafname_dict[url] = wafname
    #                 options.targets.append(url)
    #     else:
    #         exit(colorize("[x] file '%s' does not exist" % options.test_file))

    if options.proxy:
        session.proxies.update({"http": options.proxy, "https": options.proxy})

    if options.random_agent:
        revision = random.randint(20, 64)
        platform = random.sample(("X11; %s %s" % (random.sample(("Linux", "Ubuntu; Linux", "U; Linux", "U; OpenBSD", "U; FreeBSD"), 1)[0], random.sample(("amd64", "i586", "i686", "amd64"), 1)[0]), "Windows NT %s%s" % (random.sample(("5.0", "5.1", "5.2", "6.0", "6.1", "6.2", "6.3", "10.0"), 1)[0], random.sample(("", "; Win64", "; WOW64"), 1)[0]), "Macintosh; Intel Mac OS X 10.%s" % random.randint(1, 11)), 1)[0]
        user_agent = "Mozilla/5.0 (%s; rv:%d.0) Gecko/20100101 Firefox/%d.0" % (platform, revision, revision)
        HEADERS["User-Agent"] = user_agent

def format_name(waf):
    return "%s%s" % (DATA_JSON["wafs"][waf]["name"], (" (%s)" % DATA_JSON["wafs"][waf]["company"]) if DATA_JSON["wafs"][waf]["name"] != DATA_JSON["wafs"][waf]["company"] else "")

def retrieve(target, data=None):
    global proxies_index, options
    retval = {}
    if proxies:
        while True:
            try:
                proxy = {"http": proxies[proxies_index], "https": proxies[proxies_index]}
                proxies_index = (proxies_index + 1) % len(proxies)
                resp = session.get(PROXY_TESTING_PAGE, proxies=proxy, headers=HEADERS, allow_redirects=options.allow_redirect)
                none = resp.content
            except KeyboardInterrupt:
                raise
            except:
                pass
            else:
                break
    try:
        # 如果有查询参数和空格替换需求，可以使用 requests 自动处理 URL 编码
        encoded_url = "".join(target[_].replace(' ', "%20") if _ > target.find('?') else target[_] for _ in range(len(target)))
        # 如果 data 存在，发送 POST 请求；否则，发送 GET 请求
        if data:
            resp = session.post(encoded_url, data=data, headers=HEADERS, timeout=options.timeout)
        else:
            resp = session.get(encoded_url, headers=HEADERS, timeout=options.timeout)
        # 顺利获取到内容就往下面执行
        # retval存储有：URL、HTML文本、HTTP响应状态码、HTML请求RAW型式
        retval[URL] = resp.url
        retval[HTML] = resp.content
        retval[HTTPCODE] = resp.status_code
        hlHCvsn_str = "HTTP/1.1"
        retval[RAW] = "%s %d %s\n%s\n%s" % (hlHCvsn_str, retval[HTTPCODE], resp.reason, str(resp.headers), retval[HTML])
    except Exception as ex:
        retval[URL] = getattr(ex, "url", target)
        retval[HTTPCODE] = getattr(ex, "code", None)
        try:
            retval[HTML] = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", str(ex))
        except:
            retval[HTML] = ""
        hlHCvsn_str = "HTTP/1.1"
        retval[RAW] = "%s %s %s\n%s\n%s" % (hlHCvsn_str, retval[HTTPCODE] or "", getattr(ex, "msg", ""), str(ex.headers) if hasattr(ex, "headers") else "", retval[HTML])

    for encoding in re.findall(r"charset=[\s\"']?([\w-]+)", retval[RAW])[::-1] + ["utf8"]:
        encoding = ENCODING_TRANSLATIONS.get(encoding, encoding)
        try:
            retval[HTML] = retval[HTML].decode(encoding, errors="replace")
            break
        except:
            pass
    match = re.search(r"<title>\s*(?P<result>[^<]+?)\s*</title>", retval[HTML], re.I)
    retval[TITLE] = match.group("result") if match and "result" in match.groupdict() else None
    retval[TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML])
    match = re.search(r"(?im)^Server: (.+)", retval[RAW])
    retval[SERVER] = match.group(1).strip() if match else ""
    return retval

import aiohttp
ENCODING_TRANSLATIONS = {
    "windows-874": "iso-8859-11",
    "utf-8859-1": "utf8",
    "en_us": "utf8",
    "macintosh": "iso-8859-1",
    "euc_tw": "big5_tw",
    "th": "tis-620",
    "unicode": "utf8",
    "utc8": "utf8",
    "ebcdic": "ebcdic-cp-be",
    "iso-8859": "iso8859-1",
    "ansi": "ascii",
    "gbk2312": "gbk",
    "windows-31j": "cp932",
    "en": "us",
}
URL, HTML, HTTPCODE, RAW, TITLE, TEXT, SERVER = range(7)

async def async_retrieve(target, session, data=None, proxies=None, headers=None, timeout=10, proxy_testing_page="https://myexternalip.com/raw"):
    retval = {}
    proxy = None

    # 如果有代理，使用轮询的方式获取代理
    if proxies:
        proxies_index = 0
        while True:
            try:
                proxy = proxies[proxies_index]
                proxies_index = (proxies_index + 1) % len(proxies)
                # 测试代理可用性
                async with session.get(proxy_testing_page, proxy=proxy, timeout=timeout) as resp:
                    _ = await resp.read()  # 测试请求成功即可继续
                break
            except aiohttp.ClientError:
                pass  # 跳过不可用的代理
            except asyncio.CancelledError:
                raise
    try:
        # 如果有查询参数和空格替换需求，可以通过 URL 编码处理
        encoded_url = "".join(target[_].replace(' ', "%20") if _ > target.find('?') else target[_] for _ in range(len(target)))
        if data:
            # POST 请求
            async with session.post(encoded_url, data=data, headers=headers, proxy=proxy, timeout=timeout) as resp:
                content = await resp.read()
        else:
            # GET 请求
            async with session.get(encoded_url, headers=headers, proxy=proxy, timeout=timeout) as resp:
                content = await resp.read()
        retval[URL] = str(resp.url)
        retval[HTML] = content
        retval[HTTPCODE] = resp.status
        hlHCvsn_str = "HTTP/1.1"
        retval[RAW] = f"{hlHCvsn_str} {retval[HTTPCODE]} {resp.reason}\n{resp.headers}\n{retval[HTML]}"
    except Exception as ex:
        retval[URL] = target
        retval[HTTPCODE] = None
        retval[HTML] = str(ex)
        hlHCvsn_str = "HTTP/1.1"
        retval[RAW] = f"{hlHCvsn_str} {retval[HTTPCODE]} {str(ex)}"
    # 解码 HTML 内容
    for encoding in re.findall(r"charset=[\s\"']?([\w-]+)", retval[RAW])[::-1] + ["utf8"]:
        encoding = ENCODING_TRANSLATIONS.get(encoding, encoding)
        try:
            retval[HTML] = retval[HTML].decode(encoding, errors="replace")
            break
        except:
            pass
    # 提取 title 和 server 信息
    match = re.search(r"<title>\s*(?P<result>[^<]+?)\s*</title>", retval[HTML], re.I)
    retval[TITLE] = match.group("result") if match and "result" in match.groupdict() else None
    retval[TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML])
    match = re.search(r"(?im)^Server: (.+)", retval[RAW])
    retval[SERVER] = match.group(1).strip() if match else ""
    return retval

def check_payload(target, payload, original, heuristic, protection_regex=GENERIC_PROTECTION_REGEX % '|'.join(GENERIC_PROTECTION_KEYWORDS)):
    global chained
    # global heuristic
    # global intrusive
    global locked_code
    global locked_regex
    # asrg 3
    # time.sleep(options.delay or 0)
    info = ""
    if options.post:
        _ = "%s=%s" % ("".join(random.sample(string.ascii_letters, 3)), quote(payload))
        intrusive = retrieve(_)
    else:
        # arg4
        _ = "%s%s%s=%s" % (target, '?' if '?' not in target else '&', "".join(random.sample(string.ascii_letters, 3)), quote(payload))
        intrusive = retrieve(_)

    if options.lock and not payload.isdigit():
        if payload == HEURISTIC_PAYLOAD:
            # 怪不得identYwaf这么废，这里不改将毫无用处，现在哪个waf还把自己大名干到明面上
            match = re.search(re.sub(r"Server:|Protected by", "".join(random.sample(string.ascii_letters, 6)), WAF_RECOGNITION_REGEX, flags=re.I), intrusive[RAW] or "")
            if match:
                result = True

                for _ in match.groupdict():
                    if match.group(_):
                        waf = re.sub(r"\Awaf_", "", _)
                        locked_regex = DATA_JSON["wafs"][waf]["regex"]
                        locked_code = intrusive[HTTPCODE]
                        break
            else:
                result = False

            if not result:
                # 现在这里的情况很复杂，result指的是没有匹配的情况
                info += colorize("[x] can't lock results to a non-blind match")
                info += "\n" + colorize("[x] I don't know how to handle this problem")
        else:
            result = re.search(locked_regex, intrusive[RAW]) is not None and locked_code == intrusive[HTTPCODE]
    elif options.string:
        result = options.string in (intrusive[RAW] or "")
    elif options.code:
        result = options.code == intrusive[HTTPCODE]
    else:
        result = intrusive[HTTPCODE] != original[HTTPCODE] or (intrusive[HTTPCODE] != 200 and intrusive[TITLE] != original[TITLE]) or (re.search(protection_regex, intrusive[HTML]) is not None and re.search(protection_regex, original[HTML]) is None) or (difflib.SequenceMatcher(a=original[HTML] or "", b=intrusive[HTML] or "").quick_ratio() < QUICK_RATIO_THRESHOLD)

    if not payload.isdigit():
        if result:
            if options.debug:
                print("\r---%s" % (40 * ' '))
                print(payload)
                print(intrusive[HTTPCODE], intrusive[RAW])
                print("---")

            if intrusive[SERVER]:
                servers.add(re.sub(r"\s*\(.+\)\Z", "", intrusive[SERVER]))
                if len(servers) > 1:
                    chained = True
                    # info += "\n" + colorize("[!] multiple (reactive) rejection HTTP 'Server' headers detected (%s)" % ', '.join("'%s'" % _ for _ in sorted(servers)))

            if intrusive[HTTPCODE]:
                codes.add(intrusive[HTTPCODE])
                if len(codes) > 1:
                    chained = True
                    # info += "\n" + colorize("[!] multiple (reactive) rejection HTTP codes detected (%s)" % ', '.join("%s" % _ for _ in sorted(codes)))

            if heuristic and heuristic[HTML] and intrusive[HTML] and difflib.SequenceMatcher(a=heuristic[HTML] or "", b=intrusive[HTML] or "").quick_ratio() < QUICK_RATIO_THRESHOLD:
                chained = True
                # info += "\n" +  colorize("[!] multiple (reactive) rejection HTML responses detected")

    if payload == HEURISTIC_PAYLOAD:
        heuristic = intrusive

    return result, intrusive, heuristic, info

def non_blind_check(raw, silent=False):
    # global WAF_RECOGNITION_REGEX, non_blind
    # arg6
    retval = False
    info = ""
    match = re.search(WAF_RECOGNITION_REGEX, raw or "")
    if match:
        retval = True
        for _ in match.groupdict():
            if match.group(_):
                waf = re.sub(r"\Awaf_", "", _)
                if not silent:
                    info += colorize("[+] non-blind match: '%s'%s" % (format_name(waf), 20 * ' '))
    return retval, info

async def parellel_test(target, original, intrusive, heuristic, protection_regex, payloads, hostname):
    global options, DATA_JSON
    loop = asyncio.get_event_loop()
    blocked = []

    async def execute_payload(target, payloadname: str, payload, original, protection_regex, delay, counter):
        res = {
            payloadname: {}
        }
        nonlocal heuristic
        await asyncio.sleep(random.uniform(0, delay))  # 使用异步的 sleep
        if counter % VERIFY_OK_INTERVAL == 0:
            for i in range(VERIFY_RETRY_TIMES):
                benign_check = await asyncio.to_thread(
                    check_payload, target, str(random.randint(1, 9)), original, heuristic, protection_regex
                )
                if not benign_check[0]:  # 检查是否有效
                    break
                elif i == VERIFY_RETRY_TIMES - 1:
                    res[payloadname]["error"] = "RuntimeError: I can't solve it! Your IP may be banned!\n"
                    return res
                else:
                    await asyncio.sleep(random.uniform(0, 5))  # 再次异步 sleep
        # 执行实际 payload 检查
        try:
            last, new_intrusive, new_heuristic, new_info = await asyncio.to_thread(
                check_payload, target, payload, original, heuristic, protection_regex
            )
        except:
            res[payloadname]["error"] = "RuntimeError: I can't solve it!\n"
            return res
        signature = struct.pack(">H", ((calc_hash(payload, binary=False) << 1) | last) & 0xFFFF)
        # 如果 payload 有效，添加到 blocked 列表
        if last and payloadname not in blocked:
            blocked.append(payloadname)
        # 更新 heuristic
        heuristic = new_heuristic
        # 返回结果
        res = {
            payloadname: {
                "last": last,
                "payload": payload,
                "signature": signature,
                "results": "x" if last else ".",
                "info": new_info
            }
        }
        return res

    async def process_payloads():
        tasks = [
            execute_payload(
                target,
                item.split("::", 1)[0],
                item.split("::", 1)[1],
                original,
                protection_regex,
                options.delay,
                counter,
            )
            for counter, item in enumerate(payloads)
        ]
        return await asyncio.gather(*tasks)

    results2 = await process_payloads()
    return results2

def output_info(signature, results, original):
    _ = calc_hash(signature)
    signature = "%s:%s" % (
        _.encode("hex") if not hasattr(_, "hex") else _.hex(), base64.b64encode(signature).decode("ascii"))
    print(colorize("%s[=] results: '%s'" % ("\n" if IS_TTY else "", results)))
    hardness = 100 * results.count('x') // len(results)
    print(colorize("[=] hardness: %s (%d%%)" % ("insane" if hardness >= 80 else ("hard" if hardness >= 50 else ("moderate" if hardness >= 30 else "easy")),hardness)))
    if blocked:
        print(colorize("[=] blocked categories: %s" % ", ".join(blocked)))
    if not results.strip('.') or not results.strip('x'):
        print(colorize("[-] blind match: -"))
        if re.search(r"(?i)captcha", original[HTML]) is not None:
            print(colorize("[x] there seems to be an activated captcha"))
            # continue
    else:
        print(colorize("[=] signature: '%s'" % signature))
        if signature in SIGNATURES:
            waf = SIGNATURES[signature]
            print(colorize("[+] blind match: '%s' (100%%)" % format_name(waf)))
        elif results.count('x') < MIN_MATCH_PARTIAL:
            print(colorize("[-] blind match: -"))
        else:
            matches = {}
            markers = set()
            decoded = base64.b64decode(signature.split(':')[-1])
            for i in xrange(0, len(decoded), 2):
                part = struct.unpack(">H", decoded[i: i + 2])[0]
                markers.add(part)

            for candidate in SIGNATURES:
                counter_y, counter_n = 0, 0
                decoded = base64.b64decode(candidate.split(':')[-1])
                for i in xrange(0, len(decoded), 2):
                    part = struct.unpack(">H", decoded[i: i + 2])[0]
                    if part in markers:
                        counter_y += 1
                    elif any(_ in markers for _ in (part & ~1, part | 1)):
                        counter_n += 1
                result = int(round(100.0 * counter_y / (counter_y + counter_n)))
                if SIGNATURES[candidate] in matches:
                    if result > matches[SIGNATURES[candidate]]:
                        matches[SIGNATURES[candidate]] = result
                else:
                    matches[SIGNATURES[candidate]] = result
            if chained:
                for _ in list(matches.keys()):
                    if matches[_] < 90:
                        del matches[_]
            if not matches:
                print(colorize("[-] blind match: - "))
                print(colorize("[!] probably chained web protection systems"))
            else:
                matches = [(_[1], _[0]) for _ in matches.items()]
                matches.sort(reverse=True)

                print(colorize("[+] blind match: %s" % ", ".join(
                    "'%s' (%d%%)" % (format_name(matches[i][1]), matches[i][0]) for i in
                    xrange(min(len(matches), MAX_MATCHES) if matches[0][0] != 100 else 1))))

import asyncio
async def target_test(target):
    # 因为需要批量检查target，所以这里就尽量减少输出的内容，保证检测界面的简洁性，最后再将检测结果统一输出
    global HEURISTIC_PAYLOAD, DATA_JSON
    print(colorize("[i] checking target '%s'..." % target))
    hostname = target.split("//")[-1].split("/")[0].split(":")[0]
    res = {target:{}}
    res[target]["ANTI_ROBOT"] = False
    res[target]["host"] = None
    res[target]["ORIGINAL"] = None
    res[target]["new_target"] = None
    res[target]["challenge"] = None
    res[target]["INTRUSIVE"] = None
    res[target]["HEURISTIC"] = None
    res[target]["BLIND_CHECK_INFO"] = None
    res[target]["SIGNATURE"] = b""
    res[target]["RESULTS"] = ""
    res[target]["INFO"] = ""
    if not hostname.replace('.', "").isdigit():
        try:
            socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            # exit(colorize("[x] host '%s' does not exist" % hostname))
            res[target]["INFO"] += "\n" + colorize("%s [x] host '%s' does not exist" %(target, hostname))
            return res
    res[target]["host"] = hostname

    # 这里的retrieve是requests实现的，这不可以！！，必须得是异步的这里，所以我们可以这么操作，单独设计一个aiohttp版本的retrieve
    async with aiohttp.ClientSession() as session:
        original = await async_retrieve(target=target, session=session, headers=HEADERS, proxies=options.proxy)
    new_target = original[URL]

    res[target]["new_target"] = new_target
    res[target]["ORIGINAL"] = original

    if original[HTTPCODE] is None:
        # exit(colorize("[x] missing valid response"))
        res[target]["INFO"] += "\n" + colorize("[x] missing valid response. Your IP may be banned or the website has not alived")
        return res
        # continue

    if not any((options.string, options.code)) and original[HTTPCODE] >= 400:
        if original[HTTPCODE] < 500:
            check, blind_check_info  = non_blind_check(original[RAW])
            res[target]["BLIND_CHECK_INFO"] = blind_check_info
            res[target]["INFO"] += "\n" + colorize("[x] access to host '%s' seems to be restricted%s. The website may be shielded by '%s' WAF." % (hostname, (
                        " (%d: '<title>%s</title>')" % (original[HTTPCODE], original[TITLE].strip())) if original[TITLE] else "", blind_check_info if check else 'an unknown'))
            # res[target]["ORIGINAL_HTTPCODE"] = original[HTTPCODE]
            return res
        else:
            check, blind_check_info,  = non_blind_check(original[RAW])
            res[target]["BLIND_CHECK_INFO"] = blind_check_info
            res[target]["INFO"] += "\n" + colorize(
                "[x] access to host '%s' seems to be restricted%s" % (
                hostname, (" (%d: '<title>%s</title>')" % (original[HTTPCODE], original[TITLE].strip())) if original[TITLE] else ""))
            # res[target]["ORIGINAL_HTTPCODE"] = original[HTTPCODE]
            return res
        # continue

    challenge = None
    if all(_ in original[HTML].lower() for _ in ("eval", "<script")):
        match = re.search(r"(?is)<body[^>]*>(.*)</body>", re.sub(r"(?is)<script.+?</script>", "", original[HTML]))
        if re.search(r"(?i)<(body|div)", original[HTML]) is None or (match and len(match.group(1)) == 0):
            challenge = re.search(r"(?is)<script.+</script>", original[HTML]).group(0).replace("\n", "\\n")
            res[target]["challenge"] = challenge
            if all(_ in original[HTML].lower() for _ in ("var", "let", "window")):
                res[target]["INFO"] += "\n" + colorize("[x] anti-robot JS challenge detected. The site %s seems to be behind a WAF or some sort of security solution") % new_target
                res[target]["ANTI_ROBOT"] = True
                return res

    protection_keywords = GENERIC_PROTECTION_KEYWORDS
    protection_regex = GENERIC_PROTECTION_REGEX % '|'.join(keyword for keyword in protection_keywords if keyword not in original[HTML].lower())

    # print(colorize("[i] running basic heuristic test..."))
    check, intrusive, heuristic, check_payload_info = check_payload(target, HEURISTIC_PAYLOAD, original, None)
    res[target]["INTRUSIVE"] = intrusive
    res[target]["HEURISTIC"] = heuristic
    res[target]["INFO"] += "\n" + check_payload_info
    if not check:
        if new_target.startswith("https://"):
            new_target = new_target.replace("https://", "http://")
            check, intrusive, heuristic, check_payload_info = check_payload(new_target, HEURISTIC_PAYLOAD, original, heuristic)
            res[target]["INFO"] += "\n" + check_payload_info
            res[target]["INTRUSIVE"] = intrusive
            res[target]["HEURISTIC"] = heuristic
        if not check:
            nbc, blind_check_info = non_blind_check(intrusive[RAW])
            res[target]["INFO"] += "\n" + blind_check_info
            res[target]["BLIND_CHECK_INFO"] = blind_check_info
            if not nbc:
                res[target]["INFO"] += "\n" + colorize("[x] unable to continue due to static responses%s" % (" (captcha)" if re.search(r"(?i)captcha", intrusive[RAW]) is not None else ""))
            elif challenge is None:
                res[target]["INFO"] += "\n" + colorize("[x] host '%s' does not seem to be protected" % hostname)
                return res
            else:
                res[target]["INFO"] += "\n" + colorize("[x] response not changing without JS challenge solved")
                res[target]["ANTI_ROBOT"] = True
                return res

    # if options.fast and not non_blind:
    #     exit(colorize("[x] fast exit because of missing non-blind match"))

    if not intrusive[HTTPCODE]:
        res[target]["INFO"] += "\n" + colorize("[i] rejected summary: RST|DROP") + "\n"
    else:
        _ = "...".join(match.group(0) for match in re.finditer(GENERIC_ERROR_MESSAGE_REGEX, intrusive[HTML])).strip().replace("  "," ")
        res[target]["INFO"] += "\n" + colorize(("[i] rejected summary: %d ('%s%s')" % (intrusive[HTTPCODE], ("<title>%s</title>" % intrusive[TITLE]) if intrusive[TITLE] else "","" if not _ or intrusive[HTTPCODE] < 400 else ("...%s" % _))).replace(" ('')", ""))

    found, blind_check_info = non_blind_check(intrusive[RAW] if intrusive[HTTPCODE] is not None else original[RAW])
    res[target]["BLIND_CHECK_INFO"] = blind_check_info

    if not found:
        res[target]["INFO"] += "\n" + colorize("[-] non-blind match: -")
    # arg: 在这里我们设置IS_TTY=True
    IS_TTY = True
    '''-----------------------------------------------------------------------------------------------------------------------------------------------------'''
    # arg3
    payloads = DATA_JSON["payloads"]
    results = ""
    signature = b""
    flag = True
    task = asyncio.create_task(parellel_test(new_target, original, intrusive, heuristic, protection_regex, payloads, hostname))
    results2 = await task
    parellel_info = ""

    for result, payload in zip(results2, payloads):
        if result[payload.split("::", 1)[0]].get("error"):
            parellel_info += result[payload.split("::", 1)[0]].get('error')
            flag = False
            break
        signature += result[payload.split("::", 1)[0]].get('signature')
        results += result[payload.split("::", 1)[0]].get('results')
        parellel_info += result[payload.split("::", 1)[0]].get('info')
    if not flag:
        res[target]["ERROR"] = parellel_info + f"[x] host '{hostname}' seems to be misconfigured or rejecting benign requests"
        return res
    res[target]["SIGNATURE"] = signature
    res[target]["RESULTS"] = results
    res[target]["INFO"] += "\n" + parellel_info
    '''-----------------------------------------------------------------------------------------------------------------------------------------------------'''
    return res

accuracy = 0
async def run():
    global options, wafname, accuracy
    # 因为options.url换成了options.targets，所以所有关于使用options.url的函数都得变成传参的函数
    # hostname = options.url.split("//")[-1].split('/')[0].split(':')[0]
    tasks = [asyncio.create_task(target_test(target)) for target in options.targets]
    all_results = await asyncio.gather(*tasks)
    for target, results in zip(options.targets, all_results):
        print()
        print(f"[i] Results for {target}")
        flag = False
        if results:
            if results[target].get("ERROR", None):
                print(results[target]["ERROR"])
                continue
            if results[target].get("BLIND_CHECK_INFO", None):
                print(results[target]["BLIND_CHECK_INFO"])
                flag = True
            for info in results[target]["INFO"].split("\n"):
                if info:
                    print(info)
            if results[target]["SIGNATURE"] != b"" and results[target]["RESULTS"] and results[target]["ORIGINAL"]:
                if results[target]["RESULTS"] == ".............................................":
                    print(f"[x] host {target} does not seem to be protected")
                    continue
                output_info(results[target]["SIGNATURE"], results[target]["RESULTS"], results[target]["ORIGINAL"])
                continue
            if not flag:
                print(f"[x] host {target} does not find any waf.")



def main():
    if "--version" not in sys.argv:
        print(BANNER)
    parse_args()
    init()
    asyncio.run(run())

load_data()

if __name__ == "__main__":

    t1 = time.time()
    try:
        main()
    except KeyboardInterrupt:
        exit(colorize("\r[x] Ctrl-C pressed"))
    t2 = time.time()
    print(f"{t2-t1}")
