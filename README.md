<p align="center">
  <img width="300" height="300" src="/images/infoscraper.png">
</p>

# InfoScraper

![GitHub stars](https://img.shields.io/github/stars/0xsyr0/InfoScraper?logoColor=yellow) ![GitHub forks](https://img.shields.io/github/forks/0xsyr0/InfoScraper?logoColor=purple) ![GitHub watchers](https://img.shields.io/github/watchers/0xsyr0/InfoScraper?logoColor=green)</br>
![GitHub commit activity (branch)](https://img.shields.io/github/commit-activity/m/0xsyr0/InfoScraper) ![GitHub contributors](https://img.shields.io/github/contributors/0xsyr0/OSCP)

**InfoScraper** is a Python implementation of *sudosuraj's* `secret scanning JavaScript one-liner` and the `JavaScript payload` for `creating wordlists` of *renniepak* to help with bug bounty and penetration testing.

## Installation

Clone the repository and install requirements if necessary.

```console
$ git clone https://github.com/0xsyr0/InfoScraper.git
```

```console
$ pip3 install -r requirements.txt
```

## Usage

To get a list of all options and switches simple execute the script.

```console
$ python3 infoscraper.py 
+-+-+-+-+-+-+-+-+-+-+-+
|I|n|f|o|S|c|r|a|p|e|r|
+-+-+-+-+-+-+-+-+-+-+-+

usage: infoscraper.py [-h] [-u URL] [-s] [-w] [-o OUTPUT]

InfoScraper - Extract secrets and/or wordlists from a target URL.

options:
  -h, --help           show this help message and exit
  -u, --url URL        Target URL to scan
  -s, --secrets        Scan for secrets in page content
  -w, --wordlist       Generate a wordlist from the page content
  -o, --output OUTPUT  Output file to save results (optional for both modes)
```

You can test with the `test.html` before firing it against your target.

```console
$ python3 -m http.server 80
```

```console
$ python3 infoscraper.py -u http://localhost/test.html -s
+-+-+-+-+-+-+-+-+-+-+-+
|I|n|f|o|S|c|r|a|p|e|r|
+-+-+-+-+-+-+-+-+-+-+-+


[!] Potential secrets found:

CREDENTIALS
  - Enumeration
  - SuperSecret123!
  - eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
  - api_key=12345-abcde-67890-fghij
  - Test
JWT
  - eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
IPS
  - 192.168.1.100
AWSKEYS
  - AKIAIOSFODNN7EXAMPLE
EMAILS
  - admin@example.com
```

```console
$ python3 infoscraper.py -u http://localhost/test.html -w
+-+-+-+-+-+-+-+-+-+-+-+
|I|n|f|o|S|c|r|a|p|e|r|
+-+-+-+-+-+-+-+-+-+-+-+


[+] Wordlist (119 words):

<--- CUT FOR BREVITY --->
API
AWS
Code
Credentials
DOCTYPE
EXAMPLE
Email
Embedded
Enumeration
Fake
Form
HTML
Hidden
IjoxNTE
IkpXVCJ
IkpvaG
JWT
JavaScript
Key
Login
<--- CUT FOR BREVITY --->
```

## Resources

- [https://github.com/sudosuraj/Awesome-Bug-Bounty/blob/main/JSRecon.js](https://github.com/sudosuraj/Awesome-Bug-Bounty/blob/main/JSRecon.js)
- [https://x.com/renniepak/status/1780916964925345916](https://x.com/renniepak/status/1780916964925345916)