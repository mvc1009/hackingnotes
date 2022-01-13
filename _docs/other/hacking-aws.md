---
description: >-
  Amazon Web Services is a subsidiary of Amazon providing on-demand cloud
  computing platforms and APIs.
---

# Hacking AWS

## S3 Buckets

Amazon S3 has a simple web services interface that you can use to store and retrieve any amount of data, at any time, from anywhere on the web.

### AWS Configuration

You can get your credential here [https://console.aws.amazon.com/iam/home?#/security\_credential](https://console.aws.amazon.com/iam/home?#/security\_credential) but you need an aws account, free tier account : [https://aws.amazon.com/s/dm/optimization/server-side-test/free-tier/free\_np/](https://aws.amazon.com/s/dm/optimization/server-side-test/free-tier/free\_np/)

```
aws configure --profile <PROFILE_NAME>
AWSAccessKeyId= <AccessKeyID>
AWSSecretKey= <SecretKey>
Default Region Name= <Region>
Default Output Format = <json or text>
```

Or you can configure by default:

```
aws configure
```

### Search for S3 Buckets

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

### Enumeration

We will use `aws-cli` tool

* Use `--no-sign-request` for check Everyones permissions
* Use `--profile <PROFILE_NAME>` to indicate the previous configuration profile.

#### Search Buckets inside the same host:

```
aws s3 ls --endpoint-url http://s3.DOMAIN.COM/ --no-sign-request
```

#### List content of a bucket:

```
aws s3 ls s3://BUCKET-NAME --endpoint-url http://s3.DOMAIN.COM/ --no-sign-request
```

#### Copy content:

```
aws s3 cp /tmp/FILE s3://BUCKET-NAME --endpoint-url http://s3.DOMAIN.COM/ --no-sign-request
```

## DynamoDB

Amazon DynamoDB is a key-value and document database that delivers single-digit millisecond performance at any scale. It's a fully managed, multi-region, multi-active, durable database with built-in security, backup and restore, and in-memory caching for internet-scale applications.

### List tables

```
aws dynamodb list-tables --endpoint-url http://s3.DOMAIN.COM/
{
    "TableNames": [
        "TABLENAME"
    ]
}
```

### Get Table Content

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

### Create Table

```
aws dynamodb create-table --table-name TABLENAME--attribute-definitions AttributeName=title,AttributeType=S AttributeName=data,AttributeType=S --key-schema AttributeName=title,KeyType=HASH AttributeName=data,KeyType=RANGE --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 --endpoint-url http://s3.DOMAIN.COM/
```

### Create Item

```
aws dynamodb update-item --table-name TABLENAME--key file://FILE.json --endpoint-url http://s3.DOMAIN.COM/

# where FILE.json is:

{
    "title": {"S": "TITLECONTENT"},
    "data": {"S": "DATACONTENT"}
}
```

* [https://book.hacktricks.xyz/pentesting/pentesting-web/buckets/aws-s3](https://book.hacktricks.xyz/pentesting/pentesting-web/buckets/aws-s3)
* [https://docs.aws.amazon.com/cli/latest/reference/dynamodb/index.html](https://docs.aws.amazon.com/cli/latest/reference/dynamodb/index.html)
