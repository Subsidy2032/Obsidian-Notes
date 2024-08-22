## Domain Information

Domain information is the entire presence of the company in the internet, we try to understand the company's functionality and which technologies and structures are necessary for services to be offered successfully and efficiently.

We do it passively, first we should scrutinize the company website, than we should read through the texts, keeping in mind what technologies and structures are needed for those services. Than we can also use third party services.

### Online Presence

The first place to look is the SSL certificate, which can be used for several domains.

Certificate transparency is a process that intended to enable the verification of issued digital certificates for encrypted internet connections, certificates providers share the certificates with [crt.sh](https://crt.sh/) which can be used as a source to find more subdomains.

#### Output the Results from crt.sh in JSON Format
```shell-session
$ curl -s https://crt.sh/\?q\=<domain>\&output\=json | jq .
```

#### Filter the Results by Unique Subdomains
```shell-session
$ curl -s https://crt.sh/\?q\=<domain>\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
```

#### Find Company Hosted Servers (Not Including Third Party Providers)
```shell-session
$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
```

We can than run the hosts we found trough Shodan, [Shodan](https://www.shodan.io/) searches devices connected to the internet for open TCP/IP ports and filters the systems according to specific terms and criteria, we can find things such as `surveillance cameras`, `servers`, `smart home systems`, `industrial controllers`, `traffic lights` and `traffic controllers`, and various network components.

#### Shodan - IP List
```shell-session
$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done

$ for i in $(cat ip-addresses.txt);do shodan host $i;done
```

### DNS Records
```shell-session
$ dig any inlanefreight.com
```

**A records:** The IP address that points to a specific (sub)domain.

**MX records:** The mail server responsible for managing the emails for the company.

**NS records:** Name servers that are used to resolve the FQDN to IP, most hosting providers use their own name server making it easier to identify them.

**TXT records:** Often contains verification keys for different third party providers and other security aspects of DNS such as [SPF](https://datatracker.ietf.org/doc/html/rfc7208), [DMARC](https://datatracker.ietf.org/doc/html/rfc7489), and [DKIM](https://datatracker.ietf.org/doc/html/rfc6376), which are responsible for verifying and confirming the origin of the emails sent.

## Cloud Resources

### Company Hosted Servers
```shell-session
$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
```

Often cloud storage is added to the DNS list, which makes it easier to manage them.

We could also use the google dorks `inurl:` and `intext:` to find cloud storage of a company, for example `inurl:amazonaws.com intext:<company name>`, for AWS or `inurl:blob.core.windows.net intext:<company name>` for Azura.

From this point we can find many interesting files, directly or through the source code.

### Example [Domain.Glass](https://domain.glass/) Results
![[cloud1.png]]

In this example we can note the Cloudflare security measure.

### Example [GrayHatWarfare](https://buckets.grayhatwarfare.com/) Results
![[cloud2.png]]

With GrayHatWarfare we can do many different searches, discover AWS, Azura and GCP cloud storage, and even short and filter by file format, we might even find SSH private keys through the files.

Abbreviations of company name can also be a good way to discover their cloud storage.

## Staff

Searching and identifying employees on social media can lead us to identifying technologies, programming languages, and even software applications that are being used, we can also assess the person's focus based on their skills, we can use social business networks such as [LinkedIn](https://www.linkedin.com/) and [Xing](https://www.xing.de/) for this purpse.

### LinkdIn - Job Post
```txt
Required Skills/Knowledge/Experience:

* 3-10+ years of experience on professional software development projects.

« An active US Government TS/SCI Security Clearance (current SSBI) or eligibility to obtain TS/SCI within nine months.
« Bachelor's degree in computer science/computer engineering with an engineering/math focus or another equivalent field of discipline.
« Experience with one or more object-oriented languages (e.g., Java, C#, C++).
« Experience with one or more scripting languages (e.g., Python, Ruby, PHP, Perl).
« Experience using SQL databases (e.g., PostgreSQL, MySQL, SQL Server, Oracle).
« Experience using ORM frameworks (e.g., SQLAIchemy, Hibernate, Entity Framework).
« Experience using Web frameworks (e.g., Flask, Django, Spring, ASP.NET MVC).
« Proficient with unit testing and test frameworks (e.g., pytest, JUnit, NUnit, xUnit).
« Service-Oriented Architecture (SOA)/microservices & RESTful API design/implementation.
« Familiar and comfortable with Agile Development Processes.
« Familiar and comfortable with Continuous Integration environments.
« Experience with version control systems (e.g., Git, SVN, Mercurial, Perforce).

Desired Skills/Knowledge/ Experience:

« CompTIA Security+ certification (or equivalent).
« Experience with Atlassian suite (Confluence, Jira, Bitbucket).
« Algorithm Development (e.g., Image Processing algorithms).
« Software security.
« Containerization and container orchestration (Docker, Kubernetes, etc.)
« Redis.
« NumPy.
```

From a job post like this, we can see, for example, which programming languages are preferred: `Java, C#, C++, Python, Ruby, PHP, Perl`. It also required that the applicant be familiar with different databases, such as: `PostgreSQL, Mysql, and Oracle`. In addition, we know that different frameworks are used for web application development, such as: `Flask, Django, ASP.NET, Spring`.

Furthermore, we use `REST APIs, Github, SVN, and Perforce`. The job offer also results that the company works with Atlassian Suite, and therefore there may be resources that we could potentially access. We can see some skills and projects from the career history that give us a reasonable estimate of the employee's knowledge.

We could also look trough the about page of employees in LinkedIn.

With this information for example we know that Flask and Django are web frameworks for the Python programming language, so we can look at a [git repository](https://github.com/boomcamp/django-security) that describes OWSAP top 10 for Django and how it works.

We can also find important and maybe sensitive information through the Github pages of employees