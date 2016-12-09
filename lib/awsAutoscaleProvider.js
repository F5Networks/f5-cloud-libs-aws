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
'use strict';

var fs = require('fs');
var util = require('util');

var Aws = require('aws-sdk');
var q = require('q');

var MASTER_FILE_PATH = "/config/cloud/aws/master";

var AbstractAutoscaleProvider = require('../../../../f5-cloud-libs').autoscaleProvider;
var BigIp = require('../../../../f5-cloud-libs').bigIp;
var Logger = require('../../../../f5-cloud-libs').logger;
var logger;

util.inherits(AwsAutoscaleProvider, AbstractAutoscaleProvider);

 /**
  * Constructor.
  * @class
  */
function AwsAutoscaleProvider(options) {
    AwsAutoscaleProvider.super_.call(this, options);
    logger = this.logger || Logger.getLogger({logLevel: 'none'});
}

/**
 * Initialize class.
 *
 * @constructor
 * @param {Object} [options]          - Optional parameters.
 * @param {Object} [options.logger]   - A logger to use. Default to no logging.
 */
AwsAutoscaleProvider.prototype.init = function() {
    return getNodeProperties()
        .then(function(response) {
            this.nodeProperties = response;
            Aws.config.update({region: this.nodeProperties.region});
            Aws.config.credentials = new Aws.EC2MetadataCredentials({
                httpOptions: { timeout: 5000 }, // 5 second timeout
                maxRetries: 10, // retry 10 times
                retryDelayOptions: { base: 300 } // see AWS.Config for information
            });

            this.autoscaling = new Aws.AutoScaling();  // AWS autoscale object, global var
            this.s3 = new Aws.S3();  // AWS S3 object, global var
            this.ec2 = new Aws.EC2(); // AWS EC2 object. global var

            this.launchConfigMap = {}; // Map of instanceId to launch configuration

            this.launchConfigurationName = '';
        }.bind(this));
};

/**
 * Gets the instance ID of this instance
 *
 * @returns {String} The instance ID of this instance
 */
AwsAutoscaleProvider.prototype.getInstanceId = function() {
    return this.nodeProperties.instanceId;
};

/**
 * Gets info for each instance
 *
 * @returns {Object} Dictionary of instance info keyed by instance ID. Instance info is
 *                   {
 *                       isMaster: <Boolean>,
 *                       hostname: <String>,
 *                       mgmtIp: <String>,
 *                       privateIp: <String>,
 *                       mgmtPort: <Number>,
 *                       adminUser: <String>,
 *                       adminPassword: <String>
 *                   }
 */
AwsAutoscaleProvider.prototype.getInstances = function() {
    var deferred = q.defer();
    var numInstances = 0;
    var params = {
        AutoScalingGroupNames: [this.nodeProperties.autoscaleGroupId]
    };
    var instances;
    var instanceId;

    // First, get instance list from AWS
    this.autoscaling.describeAutoScalingGroups(params, function(err, data) {
        var autoscalingGroup;

        if (err) {
            logger.error('autoscaling.describeAutoScalingGroups:', err);
            deferred.reject(err);
        }
        else {
            // We need a map of launchConfigruartionName for detecting when a template update has occurred
            autoscalingGroup = data.AutoScalingGroups[0];
            numInstances = autoscalingGroup.Instances.length;
            this.launchConfigurationName = autoscalingGroup.LaunchConfigurationName;
            logger.debug('getInstanceIds: Number of instances in autoscale group:', numInstances);
            logger.debug('getInstanceIds: launchConfigurationName:', this.launchConfigurationName);
            autoscalingGroup.Instances.forEach(function(instance) {
                logger.debug('getInstanceIds: gotInstance:', instance.InstanceId);
                this.launchConfigMap[instance.InstanceId] = instance.LaunchConfigurationName;
            }.bind(this));

            // Now get info from our database
            getRegisteredInstances(this.s3, this.nodeProperties.s3Bucket, Object.keys(this.launchConfigMap))
                .then(function(response) {

                    instances = response;

                    // Make sure at least our instance ID is there
                    // In cases where instances have been scaled in and then back
                    // out, we may not have a record of ourself yet in the database,
                    // so add info we know here
                    instanceId = this.getInstanceId();
                    if (!instances[instanceId]) {
                        instances[instanceId] = {
                            isMaster: false,
                            hostname: this.nodeProperties.hostname,
                            mgmtIp: this.nodeProperties.mgmtIp,
                            privateIp: this.nodeProperties.privateIp,
                            mgmtPort: this.nodeProperties.mgmtPort,
                            adminUser: this.nodeProperties.adminUser,
                            adminPassword: this.nodeProperties.adminPassword
                        };
                    }

                    deferred.resolve(response);
                }.bind(this))
                .catch(function(err) {
                    logger.error('getInstances: getRegisteredInstances', err);
                    deferred.reject(err);
                });
        }
    }.bind(this));

    return deferred.promise;
};

/**
 * Elects a new master instance from the available instances
 *
 * @returns {String} Instance ID of the elected master
 */
AwsAutoscaleProvider.prototype.electMaster = function() {
    var deferred = q.defer();
    var electedMaster = {}; // object {iid:value, privateIp:value, hostname:value}
    var ipList = [];
    var ipToNumberList = []; // array of ip addressess converted to numbers for integer comparison
    var hostnameList = [];  // array of hostnames
    var instanceIds = [];
    var lowestIpToNumber;
    var params;
    var index;
    var key;

    // first, validate and build updated autoscale list per this node's launch config id in case of autoscale update policy
    // assume that our launch configuration is the correct one
    for (key in this.launchConfigMap){
       if (this.launchConfigMap[key] === this.launchConfigurationName) {
            instanceIds.push(key);
        }
    }

    if (instanceIds.length > 1) {
        // now elect the master
        params = {
            InstanceIds: instanceIds
        };

        this.ec2.describeInstances(params, function(err, data) {
            if (err) {
                deferred.reject(err);
            }
            else {
                logger.debug('electMaster: instances:', JSON.stringify(data));

                data.Reservations.forEach(function(reservation) {
                    reservation.Instances.forEach(function(instance) {
                        index = instanceIds.indexOf(instance.InstanceId);
                        ipList[index] = instance.PrivateIpAddress;
                        ipToNumberList[index] = ipToNumber(instance.PrivateIpAddress);
                        hostnameList[index] = instance.PrivateDnsName;
                    });
                });

                lowestIpToNumber = Math.min.apply(null, ipToNumberList);
                index = ipToNumberList.indexOf(lowestIpToNumber);

                electedMaster.iid = instanceIds[index];
                electedMaster.privateIp = ipList[index];
                electedMaster.hostname = hostnameList[index];

                logger.debug('electMaster: instanceIds:', instanceIds);
                logger.debug('electMaster: ipList:', ipList);
                logger.debug('electMaster: hostnameList:', hostnameList);
                logger.debug('electMaster: lowestIpToNumber:', lowestIpToNumber);
                logger.debug('electMaster: index of lowestIp:', index);
                logger.debug('electMaster: electedMaster:', electedMaster);

                deferred.resolve(electedMaster);
            }
        });
    }

    return deferred.promise;
};

/**
 * Determines if a given instanceId is a valid master
 *
 * Checks that the launch configuration of the specified master matches
 * our launch configuration.
 *
 * @param {String} instanceId - Instance ID to validate as a valid master.
 *
 * @returns {Boolean} Wether or not the given instanceId is a valid master
 */
AwsAutoscaleProvider.prototype.isValidMaster = function(instanceId) {
    if (this.launchConfigMap[instanceId] === this.launchConfigurationName) {
        return q(true);
    }

    return q(false);
};

/**
 * Saves instance info
 *
 * @param {Object} Instance information as returned by getInstances
 */
AwsAutoscaleProvider.prototype.putInstance = function(instance) {
    var deferred = q.defer();

    logger.debug('putInstance: instance:', instance);

    var params = {
        Bucket: this.nodeProperties.s3Bucket,
        Key: this.nodeProperties.instanceId,
        Body: JSON.stringify(instance)  // body from above
    };

    this.s3.putObject(params, function(err, data) {
        if (err) {
            deferred.reject(err);
        } else {
            if (instance.isMaster) {
                // Mark ourself as master on disk so other scripts have access to this info
                fs.closeSync(fs.openSync(MASTER_FILE_PATH, 'w'));
            }
            deferred.resolve(data);
        }
    });

    return deferred.promise;
};

/**
 * Turns on instance protection for the given instance ID
 */
AwsAutoscaleProvider.prototype.setInstanceProtection = function(instanceId) {
    instanceId = instanceId || this.getInstanceId();
    return setInstanceProtection(this.autoscaling, instanceId, this.nodeProperties.autoscaleGroupId, true);
};

/**
 * Turns off instance protection for the given instance ID
 */
AwsAutoscaleProvider.prototype.unsetInstanceProtection = function(instanceId) {
    instanceId = instanceId || this.getInstanceId();
    return setInstanceProtection(this.autoscaling, instanceId, this.nodeProperties.autoscaleGroupId, false);
};

/**
 * Reads the firstrun.conf file (generated by CFT) and returns data in a map
 */
var getFirstrunConf = function() {
    var deferred = q.defer();
    var filename = '/config/cloud/aws/firstrun.config';

    fs.readFile(filename, function (err, data) {
        var config = {};
        var dataString;
        var dataLines;
        var dataPair;

        if (err) {
            deferred.reject(err);
        }
        else {
            dataString = data.toString();
            dataLines = dataString.split("\n");
            dataLines.forEach(function(dataLine) {
                if (dataLine.search("=") > 0) {
                    dataPair = dataLine.split("=");
                    dataPair[1] = dataPair[1].replace(/'/g, "");
                    config[dataPair[0]] = dataPair[1];
                }
            });
            deferred.resolve(config);
        }
    });

    return deferred.promise;
};

/**
 * Reads the iid doc (generated by AWS) and returns data in a map
 */
var getIidDoc = function() {
    var deferred = q.defer();
    var filename = '/shared/vadc/aws/iid-document';

    fs.readFile(filename, function (err, data) {
        if (err) {
            deferred.reject(err);
        }
        else {
            deferred.resolve(JSON.parse(data.toString()));
        }
    });

    return deferred.promise;
};

/**
 * Output an object containing all settings for this F5 device
 *
 * Settings will be gathered from:
 *     1) /shared/vadc/aws/iid-document
 *     2) ./firstrun.config
 *     3) tmsh: hostname, aws access key, aws secret key
 */
var getNodeProperties = function() {
    var deferred = q.defer();
    var promises = [];

    promises.push(getFirstrunConf(), getIidDoc());
    q.all(promises)
        .then(function(responses) {
            var firstrunConf = responses[0];
            var iidDoc = responses[1];
            var properties = {};
            var bigIp;

            logger.debug('getNodeProperties: iidDoc:', iidDoc);

            properties.s3Bucket = firstrunConf.S3_BUCKET;
            properties.mgmtPort = firstrunConf.MANAGEMENT_GUI_PORT;
            properties.adminUser = 'admin';
            properties.adminPassword = firstrunConf.ADMIN_PASSWORD;

            properties.mgmtIp = iidDoc.privateIp;
            properties.privateIp = iidDoc.privateIp;
            properties.instanceId = iidDoc.instanceId;
            properties.region = iidDoc.region;

            bigIp = new BigIp(properties.privateIp, 'admin', properties.adminPassword, {port: properties.mgmtPort, logger: logger});

            bigIp.list('/tm/sys/global-settings')
                .then(function(res) {
                    properties.hostname = res.hostname;

                    bigIp.list('/tm/sys/autoscale-group')
                        .then(function(res) {
                            properties.autoscaleGroupId = res.autoscaleGroupId;
                            deferred.resolve(properties);
                });
            });
        })
        .catch(function(err) {
            deferred.reject(err);
        })
        .done();

    return deferred.promise;
};

/**
 * Gets our view of the current instances
 *
 * @param {Object} s3 - Aws.s3 instance
 * @param {String} s3Bucket - Name of S3 bucket storing our database
 * @param {String[]} instanceIds - Array of instanceIds
 *
 * @returns {Object} Object containing a dictionary of S3 objects keyed by Instance IDs
 */
var getRegisteredInstances = function(s3, s3Bucket, instanceIds) {
    var deferred = q.defer();
    var s3Dict = {};
    var params = {Bucket: s3Bucket};
    var getPromises = [];
    var keysToDelete = [];

    s3.listObjectsV2(params, function (err, data) {
        if (err) {
            logger.error('s3.listObjectsV2:', err);
            deferred.reject(err);
        }
        else {
            logger.debug('getRegistgeredInstances: S3 bucket size:', data.Contents.length);

            data.Contents.forEach(function (element) {
                logger.debug('getRegistgeredInstances: comparing with instanceIds, element.Key:', element.Key);
                if (instanceIds.indexOf(element.Key) !== -1) {
                    getPromises.push(getObject(s3, s3Bucket, element.Key));
                }
                else {
                    logger.debug('getRegistgeredInstances: bucket item not in instanceIds, mark for removal from S3');
                    keysToDelete.push(element.Key);
                }
            });
        }

        q.all(getPromises)
            .then(function(responses) {
                var i;

                logger.debug('getRegistgeredInstances: instances:', responses);

                for (i = 0; i < responses.length; ++i) {
                    s3Dict[responses[i].instanceId] = responses[i].data;
                }

                deleteObjects(s3, s3Bucket, keysToDelete)
                    .then(function() {
                        deferred.resolve(s3Dict);
                    })
                    .catch(function(err) {
                        logger.warn('Failed to delete instances', err);
                        deferred.reject(err);
                    });
            })
            .catch(function(err) {
                deferred.reject(err);
            });
    });

    return deferred.promise;
};

var getObject = function(s3, s3Bucket, key) {
    var deferred = q.defer();
    var params = {Bucket: s3Bucket, Key: key};
    logger.debug('getObject: params:', params);
    s3.getObject(params, function (err, data) {
        var parsed;
        var instanceId;
        if (err) {
            deferred.reject(err);
        }
        else {
            try {
                parsed = JSON.parse(data.Body.toString());
                // 'this' is set by the Aws SDK to a context containing the request
                instanceId = this.request.httpRequest.path.substr(1);
                logger.debug('getObject:', instanceId, JSON.stringify(parsed));
                deferred.resolve({instanceId: instanceId, data: parsed});
            }
            catch (err) {
                logger.error('getObject: err:', err);
                deferred.reject(err);
            }
        }
    });

    return deferred.promise;
};

var deleteObjects = function(s3, s3Bucket, keys) {
    var deferred = q.defer();
    var keyParams = [];

    var params;

    if (keys.length > 0) {
        keys.forEach(function(key) {
            keyParams.push({Key: key});
        });

        params = {
            Bucket: s3Bucket,
            Delete: {
                Objects: keyParams
            }
        };

        s3.deleteObjects(params, function(err, data) {
            if (err) {
                deferred.reject(err);
            }
            else {
                logger.debug('deleteObjects: success data:', data);
                deferred.resolve(data);
            }
        });
    }
    else {
        deferred.resolve();
    }

    return deferred.promise;
};

var setInstanceProtection = function(autoscaling, instanceId, autoscaleGroupId, status) {
    var deferred = q.defer();

    var params = {
        AutoScalingGroupName: autoscaleGroupId,
        InstanceIds: [ instanceId ],
        ProtectedFromScaleIn: status
    };

    autoscaling.setInstanceProtection(params, function(err, data) {
        if (err) {
            deferred.reject(err);
        } else {
            deferred.resolve(data);
        }
    });

    return deferred.promise;
};

var ipToNumber = function(ip) {
    var d = ip.split('.');
    var n = d[0] * Math.pow(256, 3);
    n += d[1] * Math.pow(256, 2);
    n += d[2] * 256;
    n += d[3];
    return n;
};

module.exports = AwsAutoscaleProvider;