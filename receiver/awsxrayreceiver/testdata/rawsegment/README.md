This folder contains raw X-Ray segment documents generated from sample application instrumented with the Go X-Ray SDK. The sample app assumes there's no DynamoDB table with the name, "does_not_exist", in the us-west-2 region. You can build the sample app using:
```
go build -tags=xraysegmentdump sample.go
```

The segments can be captured using tcpdump via the following command:
```
$ sudo tcpdump -i any -A -c100 -v -nn udp port 2000 > xray_seg.txt
```
You can safely interrupt the process after getting enough samples.