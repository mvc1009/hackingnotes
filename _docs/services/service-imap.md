# PORT 143,993/tcp - IMAP

## Internet Message Access Protocol (IMAP)

In computing, the **Internet Message Access Protocol** (**IMAP**) is an Internet standard protocol used by email clients to retrieve email messages from a mail server over a TCP/IP connection. IMAP is defined by [RFC 3501](https://tools.ietf.org/html/rfc3501).

By default, the IMAP protocol works on two ports:

* **Port 143** - this is the default IMAP non-encrypted port
* **Port 993** - this is the port you need to use if you want to connect using IMAP securely

### Connection to IMAP server

We can established our connection to both ports, non-encrypted or encypted.

```
# Non-encrypted connection
telnet imap.server.local 143

# Encrypted connection
openssl s_client -crlf -connect imap.server.local:993
```

### Login

To take a look to victims mailboxes, we obviously need their creds.

```
A1 LOGIN user@server.local password
tag LOGIN user@server.local password
```

{% hint style="warning" %}
**Note**: Sometimes the user does **not** **contains** the **domain.**
{% endhint %}

### List Mailboxes

To list mailboxes run the following command.

```
A1 LIST "" *
tag LIST "" * 
```

### Select a Mailbox

After getting the existant mailboxes we need to choose one.

```
A1 SELECT "[INBOX]"
tag SELECT "[INBOX]"
```

### Mailbox status

With status command, we can see the total of non-read messages, sent messages and more over.

```
A1 STATUS "[INBOX]" (MESSAGES)
tag STATUS "[INBOX]" (MESSAGES)
```

### Fetch headers of all messages

Fetch command gives us the ability to read the messages.

```
A1 FETCH 1:* (BODY[HEADER])
tag FETCH 1:* (BODY[HEADER])
```

### Fetch message body

To see the body of the message we need to set up the flag **BODY** as argument.

```
#Non-multipart messages
A1 FETCH [Message] (BODY)
tag FETCH [Message] (BODY)

#Multipart messages (Normaly plain text -> n=1)
A1 FETCH [Message] (BODY[n])
tag FETCH [Message] (BODY[n])
```

### Logout

Finally, when we finish out job we need to logout to close the connection.

```
A1 LOGOUT
tag LOGOUT
```

### References:

* [https://tewarid.github.io/2011/05/10/access-imap-server-from-the-command-line-using-openssl.html](https://tewarid.github.io/2011/05/10/access-imap-server-from-the-command-line-using-openssl.html)
* [https://book.hacktricks.xyz/pentesting/pentesting-imap](https://book.hacktricks.xyz/pentesting/pentesting-imap)
