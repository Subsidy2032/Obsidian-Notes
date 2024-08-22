#Web 

Easy ways for bypassing client side filtering:

1. Turn of Javascript (Provided the side does not need Javascript for basic functionality)
2. Intercept and modify the incoming page
3. Intercept and modify the file upload
4. Send the file directly to the upload point: `curl -X POST -F "submit:<value>" -F "<file-parameter>:@<path-to-file>" <site>`

