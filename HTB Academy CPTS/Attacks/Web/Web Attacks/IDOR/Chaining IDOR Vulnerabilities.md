
Usually, a `GET` request to the API endpoint should return the details of the requested user. We also notice that after the page loads, it fetches the user details with a `GET` request to the same API endpoint:
![[web_attacks_idor_get_api.jpg]]

Even if there was another form of authorization, like a JWT token. Unless it was being actively compared to the requested object details by a back-end access control system, we may still be able to retrieve other users' details.

## Information Disclosure

let's send a `GET` request with another `uid`:
![[web_attacks_idor_get_another_user.jpg]]

As we can see, this returned the details of another user, with their own `uuid` and `role`, confirming an `IDOR Information Disclosure vulnerability`:
```json
{
    "uid": "2",
    "uuid": "4a9bd19b3b8676199592a346051f950c",
    "role": "employee",
    "full_name": "Iona Franklyn",
    "email": "i_franklyn@employees.htb",
    "about": "It takes 20 years to build a reputation and few minutes of cyber-incident to ruin it."
}
```

This provides us with new details, most notably the `uuid`, which we could not calculate before, and thus could not change other users' details.

## Modifying Other Users' Details

Now, with the user's `uuid` at hand, we can change this user's details by sending a `PUT` request to `/profile/api.php/profile/2` with the above details along with any modifications we made, as follows:
![[web_attacks_idor_modify_another_user.jpg]]

We don't get any access control error messages this time, and when we try to `GET` the user details again, we see that we did indeed update their details:
![[web_attacks_idor_new_another_user_details.jpg]]

One attack the ability to change user details can allow us to perform is `modifying a user's email address` and then requesting a password reset link. Another potential attack is `placing an XSS payload in the 'about' field`, which would get executed once the user visits their `Edit profile` page, enabling us to attack the user in different ways.

## Chaining Two IDOR Vulnerabilities

We can now enumerate all users and look for other `roles`, ideally an admin role. we can also use a script to automate the process for us.

Once we enumerate all users, we will find an admin user with the following details:
```json
{
    "uid": "X",
    "uuid": "a36fa9e66e85f2dd6f5e13cad45248ae",
    "role": "web_admin",
    "full_name": "administrator",
    "email": "webadmin@employees.htb",
    "about": "HTB{FLAG}"
}
```

as we now know the admin role name (`web_admin`), we can set it to our user so we can create new users or delete current users. To do so, we will intercept the request when we click on the `Update profile` button and change our role to `web_admin`:
![[web_attacks_idor_modify_our_role.jpg]]

Now, we can refresh the page to update our cookie, or manually set it as `Cookie: role=web_admin`, and then intercept the `Update` request to create a new user and see if we'd be allowed to do so:
![[web_attacks_idor_create_new_user_2.jpg]]

We did not get an error message this time. If we send a `GET` request for the new user, we see that it has been successfully created:
![[web_attacks_idor_get_new_user.jpg]]

By combining the information we gained from the `IDOR Information Disclosure vulnerability` with an `IDOR Insecure Function Calls` attack on an API endpoint, we could modify other users' details and create/delete users while bypassing various access control checks in place. On many occasions, the information we leak through IDOR vulnerabilities can be utilized in other attacks, like IDOR or XSS, leading to more sophisticated attacks or bypassing existing security mechanisms.

With our new `role`, we may also perform mass assignments to change specific fields for all users, like placing XSS payloads in their profiles or changing their email to an email we specify.