#!/bin/bash
##############################################################################
#
# Copyright (C) 2012-2017, F5 Networks, Inc. All rights reserved.
#
# reportMetrics.sh
# Logs - reported to /var/log/aws-metrics.log
#
# This script uses CloudWatch tools to report custom BIG-IP metrics
# to CloudWatch service.
# Cloudwatch service has URLs specific to each region.
# This script determines the region in which given BIG-IP runs,
# constructrs the region specific CloudWatch URL and sends metrics.
#
# Metrics are obtained by calling tmctl.
# Some metrics, like number of currently open connections, are
# reported directly, since they represent the immediate value.
#
#
# Some stats from tmctl represent 'asbolute' values, i.e. values
# which keep accumulating from the start-up time. An example of such
# value is the number of total connections: client_side_traffic.tot_conns.
# We take 2 samples for such values, with 1 second interval, to obtain
# values/per.sec.
#
# This script sets all environment variables needed to make
# a call to CloudWatch.
#
# The dependencies
#     CloudWatch tools - need to installed on the machine.
#     Inside this script AWS_CLOUDWATCH_HOME needs to set to the root of
#     CloudWatch installation directory
#
#     Credential file - set AWS_CREDENTIAL_FILE to point to
#     a file named credential-file-path.template, which contains, on separate lines:
#        AWSAccessKeyId=_your_aws_access_key
#        AWSSecretKey=_your_aws_secret_key
##############################################################################

if [ "$#" == "0" ]; then
  bash /config/cloud/aws/node_modules/f5-cloud-libs/node_modules/f5-cloud-libs-aws/scripts/runReportMetrics.sh 2> /dev/null
else
  while getopts 'd' flag; do
    case "${flag}" in
      d) 
         bash /config/cloud/aws/node_modules/f5-cloud-libs/node_modules/f5-cloud-libs-aws/scripts/runReportMetrics.sh
         ;;
      *) 
         echo "Invalid flag"
         exit 1
         ;;
    esac
  done
fi
