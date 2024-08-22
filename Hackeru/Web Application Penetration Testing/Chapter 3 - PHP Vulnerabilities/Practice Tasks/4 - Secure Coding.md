
Code to configure two variables to contain the parameters calues whith the htmlentities function and response that will be displated containing both variables:

<html>
	<head>
		<title>Sterilize-XSS</title>
	<head>
	<body>
	</body>
	<?php
		$firstname = htmlentities($_GET['firstname']);
		$lastname = htmlentities($_GET['lastname']);
		echo "<h1>Hello</h1>".$firstname." ".$lastname.", Have a nice day!"
	?>
</html>

