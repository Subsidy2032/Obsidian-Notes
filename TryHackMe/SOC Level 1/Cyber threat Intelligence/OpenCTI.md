Open sourced platform to help manage CTI through the storage, analysis, visualisation and presentation of threat campaigns, malware and IOCs.

## OpenCTI Data Model

Manly uses the Structured Threat Information Expression (STIX2) language to structure data.

Services:

- GraphQL API: connects clients to the database and messaging system.
- Write workers: Python processes utilised to write queries asynchronously from the RabbitMQ messaging system.
- Connectors: Another set of Python processes used to ingest, enrich or export data on the platform.

|Class|Description|Examples|
|---|---|---|
|**External Input Connector**|Ingests information from external sources|CVE, MISP, TheHive, MITRE|
|**Stream Connector**|Consumes platform data stream|History, Tanium|
|**Internal Enrichment Connector**|Takes in new OpenCTI entities from user requests|Observables enrichment|
|**Internal Import File Connector**|Extracts information from uploaded reports|PDFs, STIX2 Import|
|**Internal Export File Connector**|Exports information from OpenCTI into different file formats|CSV, STIX2 export, PDF|

