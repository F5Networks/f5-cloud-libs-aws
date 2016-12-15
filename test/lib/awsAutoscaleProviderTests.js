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

var fsMock = require('fs');
var awsMock = require('aws-sdk');
var AwsAutoscaleProvider = require('../../lib/AwsAutoscaleProvider');
var BigIp = require('f5-cloud-libs').bigIp;
var provider = new AwsAutoscaleProvider();

var firstRunConf;
var iidDoc;

var instance1;
var instance2;

fsMock.readFile = function(filename, cb) {
    var data;

    switch (filename) {
        case "/config/cloud/aws/firstrun.config":
            data = firstRunConf;
            break;
        case "/shared/vadc/aws/iid-document":
            data = iidDoc;
            break;
    }

    cb(null, data);
};

fsMock.reset = function() {
    firstRunConf = undefined;
    iidDoc = undefined;
};

awsMock.config = {
    update: function(config) {
        this.configUpdate = config;
    }
};

module.exports = {
    setUp: function(callback) {
        fsMock.reset();
        callback();
    },

    testInit: {
        setUp: function(callback) {
            firstRunConf = "";
            iidDoc = "{}";

            BigIp.prototype.list = function() {
                return {
                    then: function(cb) {
                        cb({hostname: 'myhost'});
                    }
                };
            };
            callback();
        },

        testGetFirstRunConf: function(test) {
            firstRunConf = "S3_BUCKET=myS3Bucket\nMANAGEMENT_GUI_PORT=myMgmtGuiPort\nADMIN_PASSWORD=myAdminPassword";
            provider.init()
                .then(function() {
                    test.strictEqual(provider.nodeProperties.s3Bucket, 'myS3Bucket');
                    test.strictEqual(provider.nodeProperties.mgmtPort, 'myMgmtGuiPort');
                    test.strictEqual(provider.nodeProperties.adminUser, 'admin');
                    test.strictEqual(provider.nodeProperties.adminPassword, 'myAdminPassword');
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        },

        testgetFirstRunConfWithEqualsSign: function(test) {
            firstRunConf = "S3_BUCKET=myS3Bucket\nMANAGEMENT_GUI_PORT=myMgmtGuiPort\nADMIN_PASSWORD=myAd=minPassword";
            provider.init()
                .then(function() {
                    test.strictEqual(provider.nodeProperties.s3Bucket, 'myS3Bucket');
                    test.strictEqual(provider.nodeProperties.mgmtPort, 'myMgmtGuiPort');
                    test.strictEqual(provider.nodeProperties.adminUser, 'admin');
                    test.strictEqual(provider.nodeProperties.adminPassword, 'myAd=minPassword');
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        },

        testGetIidDoc: function(test) {
            iidDoc = {
                privateIp: '1.2.3.4',
                instanceId: 'myInstanceId',
                region: 'myRegion'
            };
            iidDoc = JSON.stringify(iidDoc);
            provider.init()
                .then(function() {
                    test.strictEqual(provider.nodeProperties.mgmtIp, '1.2.3.4');
                    test.strictEqual(provider.nodeProperties.privateIp, '1.2.3.4');
                    test.strictEqual(provider.nodeProperties.instanceId, 'myInstanceId');
                    test.strictEqual(provider.nodeProperties.region, 'myRegion');
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        },

        testSetRegion: function(test) {
            iidDoc = {
                region: 'myRegion'
            };
            iidDoc = JSON.stringify(iidDoc);
            provider.init()
                .then(function() {
                    test.strictEqual(awsMock.config.configUpdate.region, 'myRegion');
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        }
    },

    testGetInstances: {
        setUp: function(callback) {
            provider.nodeProperties.instanceId = 'id1';

            provider.autoscaling.describeAutoScalingGroups = function(params, cb) {
                var data = {
                    AutoScalingGroups: [
                        {
                            LaunchConfigurationName: 'mainLaunchConfig',
                            Instances: [
                                {
                                    InstanceId: 'id1',
                                    LaunchConfigurationName: 'id1LaunchConfig'
                                },
                                {
                                    InstanceId: 'id2',
                                    LaunchConfigurationName: 'id2LaunchConfig'
                                }
                            ]
                        }
                    ]
                };

                cb(null, data);
            };

            provider.s3.listObjectsV2 = function(params, cb) {
                var data = {
                    Contents: [
                        {
                            Key: 'id1'
                        },
                        {
                            Key: 'id2'
                        }
                    ]
                };

                cb(null, data);
            };

            provider.s3.getObject = function(params, cb) {
                var data;
                instance1 = {
                    isMaster: false,
                    hostname: 'hostname1',
                    mgmtIp: '1.2.3.4',
                    privateIp: '1.2.3.4',
                    mgmtPort: 1000,
                    adminUser: 'myAdminUser',
                    adminPassword: 'myAdminPassword'
                };
                instance2 = {
                    isMaster: false,
                    hostname: 'hostname2',
                    mgmtIp: '5..6.7.8',
                    privateIp: '5.6.7.8',
                    mgmtPort: 1000,
                    adminUser: 'myAdminUser',
                    adminPassword: 'myAdminPassword'
                };

                switch (params.Key) {
                    case 'id1':
                        data = {
                            Body: instance1
                        };
                        break;
                    case 'id2':
                        data = {
                            Body: instance2
                        };
                        break;
                }

                var context = {
                    request: {
                        httpRequest: {
                            path: ' ' + params.Key
                        }
                    }
                };

                data.Body = JSON.stringify(data.Body);

                cb.apply(context, [null, data]);
            };

            callback();
        },

        testLaunchConfigurationMap: function(test) {
            provider.getInstances()
                .then(function() {
                    test.strictEqual(provider.launchConfigurationName, 'mainLaunchConfig');
                    test.strictEqual(provider.launchConfigMap.id1, 'id1LaunchConfig');
                    test.strictEqual(provider.launchConfigMap.id2, 'id2LaunchConfig');
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        },

        testInstanceMap: function(test) {
            provider.getInstances()
                .then(function(instances) {
                    test.deepEqual(instances.id1, instance1);
                    test.deepEqual(instances.id2, instance2);
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        }
    }
};