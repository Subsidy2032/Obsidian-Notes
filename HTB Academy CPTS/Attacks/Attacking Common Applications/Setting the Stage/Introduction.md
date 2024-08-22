While we may encounter vulnerable versions of many common applications that suffer from known vulnerabilities, it's equally important to understand how we can abuse the built-in functionality of many of those applications to achieve remote code execution.

As organizations continue to harden their external perimeter and limit exposed services, web applications are becoming a more attractive target for malicious actors and penetration testers alike. More and more companies are transitioning to remote work and exposing (intentionally or unintentionally) applications to the outside world. These applications can serve as a foothold into the internal environment during an external assessment or as a foothold, lateral movement, or additional issue to report to our client during an internal assessment.

## Application Data

Just some of the categories of applications we may come across during a given assessment that we may be able to leverage to gain a foothold or gain access to sensitive data include:

|**Category**|**Applications**|
|---|---|
|[Web Content Management](https://enlyft.com/tech/web-content-management)|Joomla, Drupal, WordPress, DotNetNuke, etc.|
|[Application Servers](https://enlyft.com/tech/application-servers)|Apache Tomcat, Phusion Passenger, Oracle WebLogic, IBM WebSphere, etc.|
|[Security Information and Event Management (SIEM)](https://enlyft.com/tech/security-information-and-event-management-siem)|Splunk, Trustwave, LogRhythm, etc.|
|[Network Management](https://enlyft.com/tech/network-management)|PRTG Network Monitor, ManageEngine Opmanger, etc.|
|[IT Management](https://enlyft.com/tech/it-management-software)|Nagios, Puppet, Zabbix, ManageEngine ServiceDesk Plus, etc.|
|[Software Frameworks](https://enlyft.com/tech/software-frameworks)|JBoss, Axis2, etc.|
|[Customer Service Management](https://enlyft.com/tech/customer-service-management)|osTicket, Zendesk, etc.|
|[Search Engines](https://enlyft.com/tech/search-engines)|Elasticsearch, Apache Solr, etc.|
|[Software Configuration Management](https://enlyft.com/tech/software-configuration-management)|Atlassian JIRA, GitHub, GitLab, Bugzilla, Bugsnag, Bitbucket, etc.|
|[Software Development Tools](https://enlyft.com/tech/software-development-tools)|Jenkins, Atlassian Confluence, phpMyAdmin, etc.|
|[Enterprise Application Integration](https://enlyft.com/tech/enterprise-application-integration)|Oracle Fusion Middleware, BizTalk Server, Apache ActiveMQ, etc.|

## Common Applications
|Application|Description|
|---|---|
|WordPress|[WordPress](https://wordpress.org/) is an open-source Content Management System (CMS) that can be used for multiple purposes. It's often used to host blogs and forums. WordPress is highly customizable as well as SEO friendly, which makes it popular among companies. However, its customizability and extensible nature make it prone to vulnerabilities through third-party themes and plugins. WordPress is written in PHP and usually runs on Apache with MySQL as the backend.|
|Drupal|[Drupal](https://www.drupal.org/) is another open-source CMS that is popular among companies and developers. Drupal is written in PHP and supports using MySQL or PostgreSQL for the backend. Additionally, SQLite can be used if there's no DBMS installed. Like WordPress, Drupal allows users to enhance their websites through the use of themes and modules.|
|Joomla|[Joomla](https://www.joomla.org/) is yet another open-source CMS written in PHP that typically uses MySQL but can be made to run with PostgreSQL or SQLite. Joomla can be used for blogs, discussion forums, e-commerce, and more. Joomla can be customized heavily with themes and extensions and is estimated to be the third most used CMS on the internet after WordPress and Shopify.|
|Tomcat|[Apache Tomcat](https://tomcat.apache.org/) is an open-source web server that hosts applications written in Java. Tomcat was initially designed to run Java Servlets and Java Server Pages (JSP) scripts. However, its popularity increased with Java-based frameworks and is now widely used by frameworks such as Spring and tools such as Gradle.|
|Jenkins|[Jenkins](https://jenkins.io/) is an open-source automation server written in Java that helps developers build and test their software projects continuously. It is a server-based system that runs in servlet containers such as Tomcat. Over the years, researchers have uncovered various vulnerabilities in Jenkins, including some that allow for remote code execution without requiring authentication.|
|Splunk|Splunk is a log analytics tool used to gather, analyze and visualize data. Though not originally intended to be a SIEM tool, Splunk is often used for security monitoring and business analytics. Splunk deployments are often used to house sensitive data and could provide a wealth of information for an attacker if compromised. Historically, Splunk has not suffered from a considerable amount of known vulnerabilities aside from an information disclosure vulnerability ([CVE-2018-11409](https://nvd.nist.gov/vuln/detail/CVE-2018-11409)), and an authenticated remote code execution vulnerability in very old versions ([CVE-2011-4642](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-4642)).|
|PRTG Network Monitor|[PRTG Network Monitor](https://www.paessler.com/prtg) is an agentless network monitoring system that can be used to monitor metrics such as uptime, bandwidth usage, and more from a variety of devices such as routers, switches, servers, etc. It utilizes an auto-discovery mode to scan a network and then leverages protocols such as ICMP, WMI, SNMP, and NetFlow to communicate with and gather data from discovered devices. PRTG is written in [Delphi](https://en.wikipedia.org/wiki/Delphi_(software)).|
|osTicket|[osTicket](https://osticket.com/) is a widely-used open-source support ticketing system. It can be used to manage customer service tickets received via email, phone, and the web interface. osTicket is written in PHP and can run on Apache or IIS with MySQL as the backend.|
|GitLab|[GitLab](https://about.gitlab.com/) is an open-source software development platform with a Git repository manager, version control, issue tracking, code review, continuous integration and deployment, and more. It was originally written in Ruby but now utilizes Ruby on Rails, Go, and Vue.js. GitLab offers both community (free) and enterprises versions of the software.|