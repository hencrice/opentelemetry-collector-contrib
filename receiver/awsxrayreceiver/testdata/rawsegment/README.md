This folder contains raw X-Ray segment documents. The `ddbSample.txt` was generated from the sample application instrumented with the Go X-Ray SDK while the rest were synthesized manually. The sample app assumes:
1. there is a DynamoDB table with the name "xray_sample_table" in the us-west-2 region
2. there is no DynamoDB table with the name "does_not_exist" in the us-west-2 region

The segments can be captured using tcpdump via the following command:
```
$ sudo tcpdump -i any -A -c100 -v -nn udp port 2000 > xray_seg.txt
```
You can safely interrupt the process after getting enough samples.

You can build the sample app by:
```
go build -tags=xraysegmentdump sample.go
```
Provide AWS credentials via environment variables and run the sample app.