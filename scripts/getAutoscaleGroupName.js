/**
 * Copyright 2016 F5 Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var fs = require('fs');
var q = require('q');
var Aws = require('aws-sdk');

/*
GLOBAL VARS 
*/
var autoscaling;  // AWS autoscale

var getIidDoc = function() {
// Output object from fs.readFile of /shared/vadc/aws/iid-document
    var deferred = q.defer();
    var filename = '/shared/vadc/aws/iid-document';

    // logger.debug('getIidDoc(): runs'); // debug
    fs.readFile(filename, function (err,data) {
        if (err) {
            deferred.reject(err);
        }
        deferred.resolve(data);
    });
    return deferred.promise;
};

/*
 M A I N  S E C T I O N
 */

getIidDoc()
  .then(function(res) {
      var iidDoc = JSON.parse(res.toString());
      var region = iidDoc.region; // Get region from iidDoc
      var iid = iidDoc.instanceId;  // Get instanceId from iidDoc

      // AWS related global settings needed before initiating AWS objects
      // http://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/Config.html
      Aws.config.update({region: region});

      // http://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/EC2MetadataCredentials.html
      // increasing the timeout of the AWS.EC2MetadataCredentials provider by setting the httpOptions.timout options. This defaults to 1000 ms
      Aws.config.credentials = new Aws.EC2MetadataCredentials({
        httpOptions: { timeout: 5000 }, // 5 second timeout
        maxRetries: 10, // retry 10 times
        retryDelayOptions: { base: 300 } // see AWS.Config for information
      });

      // Initiating AWS objects
      autoscaling = new Aws.AutoScaling();  // AWS autoscale object, global var
      autoscaling.describeAutoScalingInstances({InstanceIds: [iid]}, function (err, data) {
                if (err) {  // an error occurred
                    deferred.reject(err);
                }
                var asg = data.AutoScalingInstances[0].AutoScalingGroupName;
                console.log(asg);
            });
  })
  .catch(function(err) {
      console.log(err);
  })
  .done();