1. Download RSAT - https://www.microsoft.com/en-us/download/details.aspx?id=45520
2. Use dsquery to enumerate the organization users - dsquery user dc=[domain],dc=[extension]
3. Use dsquery to enumerate the organization computers - dsquery computer dc=[domain],dc=[extension]