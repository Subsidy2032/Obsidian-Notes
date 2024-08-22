## Cleanup

We should make cleanup tasks like reverting minor configurations we made and deleting tools scripts uploaded to the target system, we should take detailed notes during the penetration testing process to know what to clean up, and also notify and add to our report any changes that we can't revert, for example if we no longer have access to the system.

## Documenting and Reporting

Our report should include:

- An attack chain (in the event of full internal compromise or external to internal access) detailing steps taken to achieve compromise
- A strong executive summary that a non-technical audience can understand
- Detailed findings specific to the client's environment that include a risk rating, finding impact, remediation recommendations, and high-quality external references related to the issue
- Adequate steps to reproduce each finding so the team responsible for remediation can understand and test the issue while putting fixes in place
- Near, medium, and long-term recommendations specific to the environment
- Appendices which include information such as the target scope, OSINT data (if relevant to the engagement), password cracking analysis (if relevant), discovered ports/services, compromised hosts, compromised accounts, files transferred to client-owned systems, any account creation/system modifications, an Active Directory security analysis (if relevant), relevant scan data/supplementary documentation, and any other information necessary to explain a specific finding or recommendation further

At this stage, we will create a draft report that is the first deliverable our client will receive. From here, they will be able to comment on the report and ask for any necessary clarification/modifications.

## Report Review Meeting

After the client as reviewed the report in depth, we should do a report review meeting in which we will give an overview of the report and explain are findings.

## Deliverable Acceptance

We will first deliver our client a DRAFT report, and than after they gone trough it they might want you to make some changes, this new report will be marked as FINAL.

## Post-Remediation Testing

After the remediation by the client he will send a document detailing or showing the remediation, we than will try to test each issue again and send a post-remediation report to the client.

Example of a table to include in the post-remediation report:

|#|Finding Severity|Finding Title|Status|
|---|---|---|---|
|1|High|SQL Injection|Remediated|
|2|High|Broken Authentication|Remediated|
|3|High|Unrestricted File Upload|Remediated|
|4|High|Inadequate Web and Egress Filtering|Not Remediated|
|5|Medium|SMB Signing Not Enabled|Not Remediated|
|6|Low|Directory Listing Enabled|Not Remediated|

We will also want to make proves for attacks that doesn't work anymore.

## Role of the Pentester in Remediation

We should not remediate anything by ourselves, and only give general advices and not something like rewritten piece of code, to avoid conflicts.

## Data Retention

Rules of data retention and destruction my differ from country to country and firm to firm.

"While there are currently no PCI DSS requirements regarding the retention of evidence collected by the penetration tester, it is a recommended best practice that the tester retain such evidence (whether internal to the organization or a third-party provider) for a period of time while considering any local, regional, or company laws that must be followed for the retention of evidence. This evidence should be available upon request from the target entity or other authorized entities as defined in the rules of engagement."