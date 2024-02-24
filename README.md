# Reveald

reveald is a daemon for collecting system logs and metrics, powered by kawa.

# Installation

Find the package for your OS and architecture on the releases page. Download
that file to the machine, and install somewhere visible on your $path.

    curl -L https://github.com/runreveal/reveald/releases/download/<RELEASE_VERSION>/reveald-linux-amd64.tar.gz | sudo tar --directory /usr/local/bin -xz

Copy an example config from the examples/ directory, then run it!  There is
also an example for deploying as a systemd service.  Additionally, we'll have
kubernetes examples soon.

# Getting started using Reveald

An example use case might be shipping your nginx logs to s3. Save the following
config.json, and fill in the config file.

```
{
  "sources": [
    {
      "type": "syslog",
      "addr": "0.0.0.0:5514",
      "contentType": "application/json; rrtype=nginx-json",
    },
  ],
  "destinations": [
    {
      "type": "s3",
      "bucketName": "{{YOUR-S3-BUCKET-NAME}}",
      "bucketRegion": "us-east-2",
    },
  ],
}
```

Next, add the following line to your nginx server config.

```
server {
    access_log syslog:server=127.0.0.1:5514;
    # ... other config ...
}
```

Run it!

```
$ reveald run --config config.json
```

