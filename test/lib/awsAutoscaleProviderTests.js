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
var provider;

var providerOptions = {
    s3Bucket: 'foo'
};

var iidDoc;

var instance1;
var instance2;

var deletedInstances;

fsMock.readFile = function(filename, cb) {
    var data;

    switch (filename) {
        case "/shared/vadc/aws/iid-document":
            data = iidDoc;
            break;
    }

    cb(null, data);
};

fsMock.reset = function() {
    iidDoc = undefined;
};

awsMock.config = {
    update: function(config) {
        this.configUpdate = config;
    }
};

module.exports = {
    setUp: function(callback) {
        provider = new AwsAutoscaleProvider();
        fsMock.reset();
        callback();
    },

    testInit: {
        setUp: function(callback) {
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

        testGetIidDoc: function(test) {
            iidDoc = {
                privateIp: '1.2.3.4',
                instanceId: 'myInstanceId',
                region: 'myRegion'
            };
            iidDoc = JSON.stringify(iidDoc);
            provider.init(providerOptions)
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
            provider.init(providerOptions)
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

            provider.providerOptions = providerOptions;
            provider.launchConfigMap = {};

            provider.nodeProperties = {
                instanceId: 'id1',
                hostname: 'missingHostname1',
                mgmtIp: '7.8.9.0',
                privateIp: '10.11.12.13'

            };

            provider.autoscaling = {
                describeAutoScalingGroups: function(params, cb) {
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
                }
            };

            provider.s3 = {
                listObjectsV2: function(params, cb) {
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
                },

                getObject: function(params, cb) {
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
                        mgmtIp: '5.6.7.8',
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
                },

                deleteObjects: function(params, cb) {

                    params.Delete.Objects.forEach(function(element) {
                        deletedInstances.push(element.Key);
                    });
                    cb(null, true);
                }

            };

            provider.ec2 = {
                describeInstances: function(params, cb) {
                    cb(null, {});
                }
            };

            deletedInstances = [];

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
        },

        testInstanceMapMissingInstanceId: function(test) {
            // If an instance ID is missing from the db, we should get it from
            // describe instances
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
                                },
                                {
                                    InstanceId: 'id3',
                                    LaunchConfigurationName: 'id3LaunchConfig'
                                }
                            ]
                        }
                    ]
                };

                cb(null, data);
            };

            provider.ec2.describeInstances = function(params, cb) {
                var data = {
                    Reservations: [
                        {
                            Instances: [
                                {
                                    InstanceId: 'id3',
                                    PrivateIpAddress: '7.8.9.0',
                                    PrivateDnsName: 'missingHostname3'
                                }
                            ]
                        }
                    ]
                };

                cb(null, data);
            };

            provider.getInstances()
                .then(function(instances) {
                    test.deepEqual(
                       instances.id3,
                       {
                           isMaster: false,
                           hostname: 'missingHostname3',
                           mgmtIp: '7.8.9.0',
                           privateIp: '7.8.9.0'
                        }
                    );
                    test.deepEqual(instances.id2, instance2);
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        },

        testDeleteMissingInstances: function(test) {
            provider.s3.listObjectsV2 = function(params, cb) {
                var data = {
                    Contents: [
                        {
                            Key: 'id1'
                        },
                        {
                            Key: 'id2'
                        },
                        {
                            Key: 'id3'
                        }
                    ]
                };

                cb(null, data);
            };

            provider.autoscaling.describeAutoScalingGroups = function(params, cb) {
                var data = {
                    AutoScalingGroups: [
                        {
                            LaunchConfigurationName: 'mainLaunchConfig',
                            Instances: [
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

            provider.getInstances()
                .then(function() {
                    test.strictEqual(deletedInstances.length, 2);
                    test.notStrictEqual(deletedInstances.indexOf('id1'), -1);
                    test.notStrictEqual(deletedInstances.indexOf('id3'), -1);
                })
                .catch(function(err) {
                    test.ok(false, err.message);
                })
                .finally(function() {
                    test.done();
                });
        }
    },

    testElectMaster: function(test) {
        var instances = {
            'id1': {
                privateIp: '1.2.3.4'
            },
            'id2': {
                privateIp: '1.2.4.4'
            }
        };

        provider.launchConfigurationName = 'launchConfig';
        provider.launchConfigMap = {
            'id1': 'launchConfig',
            'id2': 'launchConfig'
        };

        provider.electMaster(instances)
            .then(function(electedMasterId) {
                test.strictEqual(electedMasterId, 'id1');
            })
            .catch(function(err) {
                test.ok(false, err.message);
            })
            .finally(function() {
                test.done();
            });
    }
};