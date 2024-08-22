PHP code to display the server's parameters software and user agent when receving a parmeter massage that equals okey edit to see:

<html>
	<head>
		<title>php page</title>
	</head>
	<body>
	</body>
	<?php
		if(isset($_GET['massage'])){
			if($_GET['massage'] == 'okey'){
				echo '<h1>Server Software: '.$_SERVER['Server software'].'</h1>';
				echo '<h1>User Agent: '.$_SERVER['HTTP_USER_AGENT'].'</h1>';
			}
		}
	?>
</html>