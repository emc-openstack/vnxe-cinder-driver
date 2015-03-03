# VNXe Cinder Driver

Copyright (c) 2014 - 2015 EMC Corporation.
All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

## Overview

EMCVNXeDriver (a.k.a. VNXe Cinder Driver) is based on the SanDriver defined in Cinder, with the ability to create/delete, attach/detach volumes, create/delete snapshots, etc. 

EMCVNXeDriver performs the volume operations by Restful API management interface. 

## Supported OpenStack Release

This driver supports Juno release.

## Requirements

* VNXe OE V3.1.1
* Fibre Channel Licence (if FC is to be used)
* Internet Small Computer System Interface License (if iSCSI is to be used)
* Thin Provisioning Licence
* Unified Snapshots License

## Supported Storage Protocol

* iSCSI
* Fibre Channel

## Supported Operations

The following operations will be supported by VNXe Cinder Driver:

* Create volume
* Delete volume
* Extend volume
* Attach volume
* Detach volume
* Create snapshot
* Delete snapshot
* Copy Image to Volume
* Copy Volume to Image

## Preparation

### Install VNXe Cinder Driver

VNXe Cinder Driver (EMCVNXeDriver) is provided in the installer package consists of one python file:

        emc_vnxe.py
                                
Copy the above python file to the `cinder/volume/drivers/emc/` directory of your OpenStack node(s) where cinder-volume is running.

### San Connection

To access the storage of VNXe array, OpenStack nodes must have iSCSI or Fibre Channel connection with VNXe.

#### iSCSI

Make sure that OpenStack nodes have ethernet connection with VNXe array's iSCSI ports.

#### Fibre Channel

Make sure OpenStack nodes's FC ports and VNXe Array's FC ports are connected. If FC SAN Auto Zoning is not enabled, zoning need be set up so that OpenStack nodes' FC ports can access VNXe Array's FC ports

## Backend Configuration

Make the following changes in `/etc/cinder/cinder.conf`:

Following are the elements specific to EMC VNXe driver to be configured

        # storage protocol 
        storage_protocol = iSCSI
        # storage pool which the backend is going to manage
        storage_pool_name = StoragePool00
        # VNXe management IP 
        san_ip = 192.168.1.58
        # VNXe username
        san_login = Local/admin
        # VNXe user password
        san_password = Password123!
        # VNXe Cinder Driver EMCVNXeDriver
        volume_driver = cinder.volume.drivers.emc.emc_vnxe.EMCVNXeDriver
        # backend's name
        volume_backend_name = Storage_ISCSI_01

        [database]
        max_pool_size=20
        max_overflow=30


* where `san_ip` is one of the Management IP address of the VNXe array.
* where `storage_pool_name` is the pool user wants to create volume from. The pools can be created using Unisphere for VNXe.
* Restart of cinder-volume service is needed to make the configuration change take effect.

## Authentication

VNXe credentials are needed so that the driver could talk with the VNXe array. Credentials in Local and LDAP scopes are supported.

* Local user's san_login: Local/<username> or <username>
* LDAP user's san_login: <LDAP Domain Name>/<username>

## Multi-backend configuration

        [DEFAULT]

        enabled_backends=backendA, backendB

        [backendA]

        storage_protocol = iSCSI
        storage_pool_name = StoragePool00
        san_ip = 192.168.1.58
        san_login = Local/admin
        san_password = Password123!
        volume_driver = cinder.volume.drivers.emc.emc_vnxe.EMCVNXeDriver
        volume_backend_name = backendA

        [backendB]
        storage_protocol = FC
        storage_pool_name = StoragePool01
        san_ip = 192.168.1.58
        san_login = Local/admin
        san_password = Password123!
        volume_driver = cinder.volume.drivers.emc.emc_vnxe.EMCVNXeDriver
        volume_backend_name = backendB

        [database]

        max_pool_size=20
        max_overflow=30

For more details on multi-backend, see [OpenStack Administration Guide](http://docs.openstack.org/admin-guide-cloud/content/multi_backend.html)

## Restriction of deployment

It is not suggest to deploy the driver on Nova Compute Node if "cinder upload-to-image --force True" is to be used against an in-use volume. Otherwise, "cinder upload-to-image --force True" will terminate the VM instance's data access to the volume.

## Thick/Thin Provisioning

Use Cinder Volume Type to define a provisioning type and the provisioning type could be either thin or thick.

Here is an example of how to create thick/thin volume. First create volume types. Then define extra specs for each volume type.

        cinder --os-username admin --os-tenant-name admin type-create "ThickVolume"
        cinder --os-username admin --os-tenant-name admin type-create "ThinVolume"
        cinder --os-username admin --os-tenant-name admin type-key "ThickVolume" set storagetype:provisioning=thick
        cinder --os-username admin --os-tenant-name admin type-key "ThinVolume" set storagetype:provisioning=thin

In the example above, two volume types are created: `ThickVolume` and `ThinVolume`. For `ThickVolume`, `storagetype:provisioning` is set to `thick`. Similarly for `ThinVolume`. If `storagetype:provisioning` is not specified, default value `thick` is adopted.

Volume Type names `ThickVolume` and `ThinVolume` are user-defined and can be any names. Extra spec key `storagetype:provisioning` has to be the exact name listed here. Extra spec value for `storagetype:provisioning` has to be either `thick` or `thin`.
During volume creation, if the driver find `storagetype:provisioning` in the extra spec of the Volume Type, it will create the volume of the provisioning type accordingly. Otherwise, the volume will be default to thick.

## FC SAN Auto Zoning

VNXe cinder driver supports FC SAN auto zoning when ZoneManager is configured. Set "zoning_mode" to "fabric" in default section to enable this feature. For ZoneManager configuration, please refer to Block Storage official guide.

## Read-only Volumes

OpenStack support read-only volumes. Administrators can use following command to set a volume as read-only.

        cinder --os-username admin --os-tenant-name admin readonly-mode-update <volume> True

After a volume is marked as read-only, the driver will forward the information when a hypervisor is attaching the volume and the hypervisor will have implementation-specific way to make sure the volume is not written.
