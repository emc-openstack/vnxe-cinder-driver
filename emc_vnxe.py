# Copyright (c) 2014 - 2015 EMC Corporation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
Drivers for EMC VNXe array based on RESTful API.
"""

import cookielib
import json
import random
import re
import urllib2

from oslo.config import cfg
import taskflow.engines
from taskflow.patterns import linear_flow
from taskflow import task
from taskflow.utils import misc

from cinder import exception
from cinder.i18n import _
from cinder.openstack.common import lockutils
from cinder.openstack.common import log as logging
from cinder.volume.configuration import Configuration
from cinder.volume.drivers.san import san
from cinder.volume import manager
from cinder.volume import volume_types
from cinder.zonemanager.utils import AddFCZone
from cinder.zonemanager.utils import RemoveFCZone

LOG = logging.getLogger(__name__)


CONF = cfg.CONF
VERSION = '00.03.00'

GiB = 1024 * 1024 * 1024

loc_opts = [
    cfg.StrOpt('storage_pool_name',
               default=None,
               help='Name of storage pool for storage allocation'),
    cfg.StrOpt('storage_protocol',
               default='iSCSI',
               help='Protocol to access the storage '
                    'allocated from this Cinder backend')]

CONF.register_opts(loc_opts)


class EMCUnityRESTClient(object):
    """EMC Unity Client interface handing REST calls and responses."""

    HEADERS = {'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Accept_Language': 'en_US',
               'Visibility': 'Enduser',
               'X-EMC-REST-CLIENT': 'true',
               'User-agent': 'EMC-OpenStack'}
    HostTypeEnum_HostManual = 1
    HostLUNTypeEnum_LUN = 1
    HostLUNAccessEnum_NoAccess = 0
    HostLUNAccessEnum_Production = 1

    def __init__(self, host, port=443, user='Local/admin',
                 password='', realm='Security Realm',
                 debug=False):
        self.mgmt_url = 'https://%(host)s:%(port)s' % {'host': host,
                                                       'port': port}
        self.debug = debug
        https_hander = urllib2.HTTPSHandler()
        cookie_jar = cookielib.CookieJar()
        cookie_hander = urllib2.HTTPCookieProcessor(cookie_jar)
        passwd_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        passwd_mgr.add_password(realm,
                                self.mgmt_url,
                                user,
                                password)
        auth_handler = urllib2.HTTPBasicAuthHandler(passwd_mgr)
        self.url_opener = urllib2.build_opener(https_hander,
                                               cookie_hander,
                                               auth_handler)

    def _http_log_req(self, req):
        if not self.debug:
            return

        string_parts = ['curl -i']
        string_parts.append(' -X %s' % req.get_method())

        for k in req.headers:
            header = ' -H "%s: %s"' % (k, req.headers[k])
            string_parts.append(header)

        if req.data:
            string_parts.append(" -d '%s'" % (req.data))
        string_parts.append(' ' + req.get_full_url())
        LOG.debug("\nREQ: %s\n", "".join(string_parts))

    def _http_log_resp(self, resp, body, failed_req=None):
        if not self.debug and failed_req is None:
            return
        if failed_req:
            LOG.error(
                _('REQ: [%(method)s] %(url)s %(req_hdrs)s\n'
                  'REQ BODY: %(req_b)s\n'
                  'RESP: [%(code)s] %(resp_hdrs)s\n'
                  'RESP BODY: %(resp_b)s\n') %
                {'method': failed_req.get_method(),
                 'url': failed_req.get_full_url(),
                 'req_hdrs': failed_req.headers,
                 'req_b': failed_req.data,
                 'code': resp.getcode(),
                 'resp_hdrs': str(resp.headers).replace('\n', '\\n'),
                 'resp_b': body})
        else:
            LOG.debug(
                "RESP: [%s] %s\nRESP BODY: %s\n",
                resp.getcode(),
                str(resp.headers).replace('\n', '\\n'),
                body)

    def _http_log_err(self, err, req):
        LOG.error(
            _('REQ: [%(method)s] %(url)s %(req_hdrs)s\n'
              'REQ BODY: %(req_b)s\n'
              'ERROR CODE: [%(code)s] \n'
              'ERROR REASON: %(resp_e)s\n') %
            {'method': req.get_method(),
             'url': req.get_full_url(),
             'req_hdrs': req.headers,
             'req_b': req.data,
             'code': err.code,
             'resp_e': err.reason})

    def _request(self, rel_url, req_data=None, method=None,
                 return_rest_err=True):
        req_body = None if req_data is None else json.dumps(req_data)
        err = None
        resp_data = None
        url = self.mgmt_url + rel_url
        req = urllib2.Request(url, req_body, EMCUnityRESTClient.HEADERS)
        if method not in (None, 'GET', 'POST'):
            req.get_method = lambda: method
        self._http_log_req(req)
        try:
            resp = self.url_opener.open(req)
            resp_body = resp.read()
            resp_data = json.loads(resp_body) if resp_body else None
            self._http_log_resp(resp, resp_body)
        except urllib2.HTTPError as http_err:
            if hasattr(http_err, 'read'):
                resp_body = http_err.read()
                self._http_log_resp(http_err, resp_body, req)
                if resp_body:
                    err = json.loads(resp_body)['error']
                else:
                    err = {'errorCode': -1,
                           'httpStatusCode': http_err.code,
                           'messages': str(http_err),
                           'request': req}
            else:
                self._http_log_err(http_err, req)
                resp_data = http_err.reason
                err = {'errorCode': -1,
                       'httpStatusCode': http_err.code,
                       'messages': str(http_err),
                       'request': req}

            if not return_rest_err:
                raise exception.VolumeBackendAPIException(data=err)
        return (err, resp_data) if return_rest_err else resp_data

    @staticmethod
    def _get_content_list(resp):
        return [entry['content'] for entry in resp['entries']]

    def _filter_by_fields(self, category, conditions, fields=None):
        filters = map(lambda entry: '%(f)s %(o)s "%(v)s"' %
                      {'f': entry[0], 'o': entry[1], 'v': entry[2]},
                      conditions)
        filter_str = ' and '.join(filters)
        filter_str = urllib2.quote(filter_str)
        get_by_fields_url =\
            '/api/types/%(category)s/instances?filter=%(filter)s'\
            % {'category': category, 'filter': filter_str}
        if fields:
            get_by_fields_url += '&fields=%s' % \
                (','.join(map(urllib2.quote, fields)))
        err, resp = self._request(get_by_fields_url)
        return () if err else self._get_content_list(resp)

    def _filter_by_field(self, category,
                         field, value,
                         fields=None):
        return self._filter_by_fields(category,
                                      ((field, 'eq', value),),
                                      fields)

    def _get_all(self, category, fields=None):
        get_all_url = '/api/types/%s/instances' % category
        if fields:
            get_all_url += '?fields=%s' % (','.join(fields))
        resp = self._request(get_all_url, return_rest_err=False)
        return self._get_content_list(resp)

    def _filter_by_id(self, category, obj_id, fields):
        get_by_id_url = '/api/instances/%(category)s/%(obj_id)s' %\
            {'category': category, 'obj_id': obj_id}
        if fields:
            get_by_id_url += '?fields=%s' % (','.join(fields))
        err, resp = self._request(get_by_id_url)
        return () if err else (resp['content'],)

    def get_pools(self, fields=None):
        return self._get_all('pool', fields)

    def get_pool_by_name(self, pool_name, fields=None):
        return self._filter_by_field('pool', 'name', pool_name, fields)

    def get_pool_by_id(self, pool_id, fields=None):
        return self._filter_by_id('pool', pool_id, fields)

    def get_lun_by_name(self, lun_name, fields=None):
        return self._filter_by_field('lun', 'name', lun_name, fields)

    def get_lun_by_id(self, lun_id, fields=None):
        return self._filter_by_id('lun', lun_id, fields)

    def get_basic_system_info(self, fields=None):
        return self._get_all('basicSystemInfo', fields)

    def create_lun(self, pool_id, name, size, **kwargs):
        lun_create_url = '/api/types/storageResource/action/createLun'
        lun_parameters = {'pool': {"id": pool_id},
                          'isThinEnabled': True,
                          'size': size}
        if 'is_thin' in kwargs:
            lun_parameters['isThinEnabled'] = kwargs['is_thin']
        # More Advance Feature
        data = {'name': name,
                'description': name,
                'lunParameters': lun_parameters}
        err, resp = self._request(lun_create_url, data)
        return (err, None) if err else \
            (err, resp['content']['storageResource'])

    def delete_lun(self, lun_id, force_snap_deletion=False):
        lun_delete_url = '/api/instances/storageResource/%s' % lun_id
        data = {'forceSnapDeletion': force_snap_deletion}
        err, resp = self._request(lun_delete_url, data, 'DELETE')
        return err, resp

    def get_hosts(self, fields=None):
        return self._get_all('host', fields)

    def get_host_by_name(self, hostname, fields=None):
        return self._filter_by_field('host', 'name', hostname, fields)

    def get_host_by_id(self, host_id, fields=None):
        return self._filter_by_id('host', host_id, fields)

    def create_host(self, hostname):
        host_create_url = '/api/types/host/instances'
        data = {'type': EMCUnityRESTClient.HostTypeEnum_HostManual,
                'name': hostname}
        err, resp = self._request(host_create_url, data)
        return (err, None) if err else (err, resp['content'])

    def delete_host(self, host_id):
        host_delete_url = '/api/instances/host/%s' % host_id
        err, resp = self._request(host_delete_url, None, 'DELETE')
        return err, resp

    def create_initiator(self, initiator_uid, host_id):
        initiator_create_url = '/api/types/hostInitiator/instances'
        data = {'host': {'id': host_id},
                'initiatorType': 2 if initiator_uid.lower().find('iqn') == 0
                else 1,
                'initiatorWWNorIqn': initiator_uid}
        err, resp = self._request(initiator_create_url, data)
        return (err, None) if err else (err, resp['content'])

    def register_initiator(self, initiator_id, host_id):
        initiator_register_url = \
            '/api/instances/hostInitiator/%s/action/register' % initiator_id
        data = {'host': {'id': host_id}}
        err, resp = self._request(initiator_register_url, data)
        return err, resp

    def get_initiators(self, fields=None):
        return self._get_all('hostInitiator', fields)

    def get_initiator_by_uid(self, initiator_uid, fields=None):
        return self._filter_by_field('hostInitiator',
                                     'initiatorId', initiator_uid,
                                     fields)

    def get_initiator_paths_by_initiator_id(self, initiator_id, fields=None):
        conditions = (('id', 'lk', initiator_id + '%'),)
        return self._filter_by_fields('hostInitiatorPath', conditions, fields)

    def get_host_luns(self, fields=None):
        return self._get_all('hostLUN', fields)

    def get_host_lun_by_ends(self, host_id, lun_id,
                             use_type=None, fields=None):
        use_type = self.HostLUNTypeEnum_LUN if use_type is None else use_type
        conditions = (('id', 'lk', '%%%(host)s_%(lun)s%%' %
                       {'host': host_id, 'lun': lun_id}),
                      ('type', 'eq', use_type))
        return self._filter_by_fields('hostLUN', conditions, fields)

    def get_iscsi_portals(self, fields=None):
        return self._get_all('iscsiPortal', fields)

    def get_iscsi_nodes(self, fields=None):
        return self._get_all('iscsiNode', fields)

    def get_ethernet_ports(self, fields=None):
        return self._get_all('ethernetPort', fields)

    def get_fc_ports(self, fields=None):
        return self._get_all('fcPort', fields)

    def expose_lun(self, lun_id, host_id):
        lun = self.get_lun_by_id(lun_id)
        if not lun:
            raise exception.VolumeBackendAPIException(
                data='%s is not found.' % lun_id)
        lun_modify_url = \
            '/api/instances/storageResource/%s/action/modifyLun' % lun_id
        lun = lun[0]
        host_access_list = lun['hostAccess'] if 'hostAccess' in lun else []
        host_access_list.append(
            {'host': {'id': host_id},
             'accessMask': self.HostLUNAccessEnum_Production})
        data = {'lunParameters': {'hostAccess': host_access_list}}
        err, resp = self._request(lun_modify_url, data)
        return err, resp

    def hide_lun(self, lun_id, host_id):
        luns = self.get_lun_by_id(lun_id)
        if len(luns) == 0:
            raise exception.VolumeBackendAPIException(
                data='%s is not found' % lun_id)
        lun_modify_url = \
            '/api/instances/storageResource/%s/action/modifyLun' % lun_id
        lun = luns[0]
        host_access_list = lun['hostAccess'] if 'hostAccess' in lun else []
        host_access_list = filter(lambda entry: entry['host']['id'] != host_id,
                                  host_access_list)
        host_access_list.append(
            {'host': {'id': host_id},
             'accessMask': self.HostLUNAccessEnum_NoAccess})
        data = {'lunParameters': {'hostAccess': host_access_list}}
        err, resp = self._request(lun_modify_url, data)
        return err, resp

    def get_snap_by_name(self, snap_name, fields=None):
        """Get the snap properties by name.
        """
        return self._filter_by_field('snap', 'name', snap_name, fields)

    def create_snap(self, lun_id, snap_name, snap_description=None):
        create_snap_url = '/api/types/snap/instances'
        req_data = {'storageResource': {'id': lun_id},
                    'name': snap_name}
        if snap_description:
            req_data['description'] = snap_description
        err, resp = self._request(create_snap_url, req_data)
        return (err, None) if err else \
            (err, resp['content']['id'])

    def delete_snap(self, snap_id):
        """The function will delete the snap by the snap_id.
        """
        delete_snap_url = '/api/instances/snap/%s' % snap_id
        err, resp = self._request(delete_snap_url, None, 'DELETE')
        return err, resp

    def extend_lun(self, lun_id, size):
        luns = self.get_lun_by_id(lun_id)
        if len(luns) == 0:
            raise exception.VolumeBackendAPIException(
                data='%s is not found.' % lun_id)
        lun_modify_url = \
            '/api/instances/storageResource/%s/action/modifyLun' % lun_id
        data = {'lunParameters': {'size': size}}
        err, resp = self._request(lun_modify_url, data)
        # 108007456: there is nothing to modify
        return err, resp

    def modify_lun_name(self, lun_id, new_name):
        """modify the lun name"""
        lun_modify_url = \
            '/api/instances/storageResource/%s/action/modifyLun' % lun_id
        data = {'name': new_name}
        err, resp = self._request(lun_modify_url, data)
        if err:
            if (str(err['messages'][0]['en-US']).find(
                    'Error Code:0x6701020') >= 0):
                msg = (_('The new name %(name)s for lun '
                       '%(lun)s already exists.') %
                       {'name': new_name, 'lun': lun_id})
                LOG.warn(msg)
            else:
                reason = (_('Manage existing lun failed. Can not '
                          'rename the lun %(lun)s to %(name)s') %
                          {'lun': lun_id, 'name': new_name})
                raise exception.VolumeBackendAPIException(
                    data=reason)


class ArrangeHostTask(task.Task):

    def __init__(self, helper, connector):
        LOG.debug('ArrangeHostTask.__init__ %s', connector)
        super(ArrangeHostTask, self).__init__(provides='host_id')
        self.helper = helper
        self.connector = connector

    def execute(self, *args, **kwargs):
        LOG.debug('ArrangeHostTask.execute %s', self.connector)
        host_id = self.helper.arrange_host(self.connector)
        return host_id


class ExposeLUNTask(task.Task):
    def __init__(self, helper, volume):
        LOG.debug('ExposeLUNTask.__init__ %s', volume)
        super(ExposeLUNTask, self).__init__()
        self.helper = helper
        self.volume = volume

    def execute(self, host_id):
        LOG.debug('ExposeLUNTask.execute %(vol)s %(host)s'
                  % {'vol': self.volume,
                     'host': host_id})
        self.helper.expose_lun(self.volume, host_id)

    def revert(self, result, host_id, *args, **kwargs):
        LOG.warn(_('ExposeLUNTask.revert %(vol)s %(host)s') %
                 {'vol': self.volume, 'host': host_id})
        if isinstance(result, misc.Failure):
            LOG.warn(_('ExposeLUNTask.revert: Nothing to revert'))
            return
        else:
            LOG.warn(_('ExposeLUNTask.revert: hide_lun'))
            self.helper.hide_lun(self.volume, host_id)


class GetConnectionInfoTask(task.Task):

    def __init__(self, helper, volume, connector, *argv, **kwargs):
        LOG.debug('GetConnectionInfoTask.__init__ %(vol)s %(conn)s' %
                  {'vol': volume, 'conn': connector})
        super(GetConnectionInfoTask, self).__init__(provides='connection_info')
        self.helper = helper
        self.volume = volume
        self.connector = connector

    def execute(self, host_id):
        LOG.debug('GetConnectionInfoTask.execute %(vol)s %(conn)s %(host)s'
                  % {'vol': self.volume, 'conn': self.connector,
                     'host': host_id})
        return self.helper.get_connection_info(self.volume,
                                               self.connector,
                                               host_id)


class EMCUnityHelper(object):

    stats = {'driver_version': VERSION,
             'storage_protocol': None,
             'free_capacity_gb': 'unknown',
             'reserved_percentage': 0,
             'total_capacity_gb': 'unknown',
             'vendor_name': 'EMC',
             'volume_backend_name': None}

    def __init__(self, conf):
        self.configuration = conf
        self.configuration.append_config_values(loc_opts)
        self.configuration.append_config_values(san.san_opts)
        self.storage_protocol = conf.storage_protocol
        self.supported_storage_protocols = ('iSCSI', 'FC')
        if self.storage_protocol not in self.supported_storage_protocols:
            msg = _('storage_protocol %(invalid)s is not supported. '
                    'The valid one should be among %(valid)s.') %\
                {'invalid': self.storage_protocol,
                 'valid': self.supported_storage_protocols}
            LOG.error(msg)
            raise exception.VolumeBackendAPIException(data=msg)
        self.active_storage_ip = self.configuration.san_ip
        self.storage_username = self.configuration.san_login
        self.storage_password = self.configuration.san_password
        self.lookup_service_instance = None
        # Here we use group config to keep same as cinder manager
        zm_conf = Configuration(manager.volume_manager_opts)
        if (zm_conf.safe_get('zoning_mode') == 'fabric' or
                self.configuration.safe_get('zoning_mode') == 'fabric'):
            from cinder.zonemanager.fc_san_lookup_service \
                import FCSanLookupService
            self.lookup_service_instance = \
                FCSanLookupService(configuration=self.configuration)
        self.client = EMCUnityRESTClient(self.active_storage_ip, 443,
                                         self.storage_username,
                                         self.storage_password,
                                         debug=CONF.debug)
        system_info = self.client.get_basic_system_info(('name',))
        if not system_info:
            msg = _('Basic system information is unavailable.')
            LOG.error(msg)
            raise exception.VolumeBackendAPIException(data=msg)
        self.storage_serial_number = system_info[0]['name']
        pool_name = self.configuration.storage_pool_name
        if pool_name is None:
            msg = _("Mandatory option storage_pool_name is missing")
            LOG.error(msg)
            raise exception.VolumeBackendAPIException(data=msg)
        pool = self.client.get_pool_by_name(pool_name, ('id',))
        if not pool:
            msg = _("Pool %s is not found.") % pool_name
            LOG.error(msg)
            raise exception.VolumeBackendAPIException(data=msg)
        self.pool_id = pool[0]['id']
        LOG.info(_('ID of Pool "%(name)s" is %(id)s') % {'name': pool_name,
                                                         'id': self.pool_id})
        self.storage_targets = self._get_storage_targets()

    def _get_iscsi_targets(self):
        res = {'a': [], 'b': []}
        node_dict = {}
        for node in self.client.get_iscsi_nodes(('id', 'name')):
            node_dict[node['id']] = node['name']
        fields = ('id', 'ipAddress', 'ethernetPort', 'iscsiNode')
        pat = re.compile(r'sp(a|b)', flags=re.IGNORECASE)
        for portal in self.client.get_iscsi_portals(fields):
            eth_id = portal['ethernetPort']['id']
            node_id = portal['iscsiNode']['id']
            m = pat.match(eth_id)
            if m:
                sp = m.group(1).lower()
                item = (node_dict[node_id], portal['ipAddress'],
                        portal['id'])
                res[sp].append(item)
            else:
                msg = _('SP of %s is unknown') % portal['id']
                LOG.warn(msg)
        return res

    def _get_fc_targets(self):
        res = {'a': [], 'b': []}
        fields = ('id', 'wwn', 'storageProcessorId')
        pat = re.compile(r'sp(a|b)', flags=re.IGNORECASE)
        for port in self.client.get_fc_ports(fields):
            sp_id = port['storageProcessorId']['id']
            m = pat.match(sp_id)
            if m:
                sp = m.group(1).lower()
                wwn = port['wwn'].replace(':', '')
                node_wwn = wwn[0:16]
                port_wwn = wwn[16:32]
                item = (node_wwn, port_wwn, port['id'])
                res[sp].append(item)
            else:
                msg = _('SP of %s is unknown') % port['id']
                LOG.warn(msg)
        return res

    def _get_storage_targets(self):
        if self.storage_protocol == 'iSCSI':
            return self._get_iscsi_targets()
        elif self.storage_protocol == 'FC':
            return self._get_fc_targets()
        else:
            return {'a': [], 'b': []}

    @staticmethod
    def _get_volumetype_extraspecs(volume):
        specs = {}

        type_id = volume['volume_type_id']
        if type_id is not None:
            specs = volume_types.get_volume_type_extra_specs(type_id)

        return specs

    @staticmethod
    def _load_provider_location(provider_location):
        pl_dict = {}
        for item in provider_location.split('|'):
            k_v = item.split('^')
            if len(k_v) == 2 and k_v[0]:
                pl_dict[k_v[0]] = k_v[1]
        return pl_dict

    @staticmethod
    def _dumps_provider_location(pl_dict):
        return '|'.join([k + '^' + pl_dict[k] for k in pl_dict])

    def create_volume(self, volume):
        name = volume['name']
        size = volume['size'] * GiB
        extra_specs = self._get_volumetype_extraspecs(volume)
        k = 'storagetype:provisioning'
        is_thin = False
        if k in extra_specs:
            v = extra_specs[k].lower()
            if v == 'thin':
                is_thin = True
            elif v == 'thick':
                is_thin = False
            else:
                msg = _('Value %(v)s of %(k)s is invalid') % {'k': k, 'v': v}
                LOG.error(msg)
                raise exception.VolumeBackendAPIException(data=msg)
        err, lun = self.client.create_lun(self.pool_id, name, size,
                                          is_thin=is_thin)
        if err:
            raise exception.VolumeBackendAPIException(data=err['messages'])
        pl_dict = {'system': self.storage_serial_number,
                   'type': 'lun',
                   'id': lun['id']}
        model_update = {'provider_location':
                        self._dumps_provider_location(pl_dict)}
        volume['provider_location'] = model_update['provider_location']
        return model_update

    def create_volume_from_snapshot(self, volume, snapshot):
        # To be implemented with Replication and TaskFlow
        raise NotImplementedError()
        pl_dict = {'system': self.storage_serial_number,
                   'type': 'lun',
                   'id': 'unknown yet'}
        model_update = {'provider_location':
                        self._dumps_provider_location(pl_dict)}
        volume['provider_location'] = model_update['provider_location']
        return model_update

    def create_cloned_volume(self, volume, src_vref):
        # To be implemented with Replication and TaskFlow
        raise NotImplementedError()
        pl_dict = {'system': self.storage_serial_number,
                   'type': 'lun',
                   'id': 'unknown yet'}
        model_update = {'provider_location':
                        self._dumps_provider_location(pl_dict)}
        volume['provider_location'] = model_update['provider_location']
        return model_update

    def _extra_lun_or_snap_id(self, volume):
        if volume.get('provider_location') is None:
            return None
        pl_dict = self._load_provider_location(volume['provider_location'])
        res_type = pl_dict.get('type', None)
        if 'lun' == res_type or 'snap' == res_type:
            if pl_dict.get('id', None):
                return pl_dict['id']
        msg = _('Fail to find LUN ID of %(vol)s in from %(pl)s') % \
            {'vol': volume['name'], 'pl': volume['provider_location']}
        LOG.error(msg)
        raise exception.VolumeBackendAPIException(data=msg)

    def delete_volume(self, volume):
        lun_id = self._extra_lun_or_snap_id(volume)
        lun = self.client.get_lun_by_id(lun_id, ('id',))
        if not lun:
            msg = _('LUN %(lun)s backing Vol %(vol)s had been deleted') %\
                {'lun': lun_id, 'vol': volume['name']}
            LOG.warn(msg)
            return
        err, resp = self.client.delete_lun(lun_id)
        if err:
            print(resp)  # Get rid of warning
            raise exception.VolumeBackendAPIException(data=err['messages'])

    def create_snapshot(self, snapshot, name, snap_desc):
        """This function will create a snapshot of the given
        volume.
        """
        LOG.debug('Entering EMCUnityHelper.create_snapshot.')
        lun_id = self._extra_lun_or_snap_id(snapshot['volume'])
        if not lun_id:
            msg = _('Failed to get LUN ID for volume %s') %\
                snapshot['volume']['name']
            raise exception.VolumeBackendAPIException(data=msg)
        err, snap_id = self.client.create_snap(
            lun_id, name, snap_desc)
        if err:
            raise exception.VolumeBackendAPIException(data=err['messages'])
        else:
            pl_dict = {'system': self.storage_serial_number,
                       'type': 'snap',
                       'id': snap_id}
            model_update = {'provider_location':
                            self._dumps_provider_location(pl_dict)}
            snapshot['provider_location'] = model_update['provider_location']
            return model_update

    def delete_snapshot(self, snapshot):
        """This function will get the snap id by the snap name
        and delete the snapshot.
        """
        snap_id = self._extra_lun_or_snap_id(snapshot)
        if not snap_id:
            return
        err, resp = self.client.delete_snap(snap_id)
        if err:
            raise exception.VolumeBackendAPIException(data=err['messages'])

    def extend_volume(self, volume, new_size):
        lun_id = self._extra_lun_or_snap_id(volume)
        err, resp = self.client.extend_lun(lun_id, new_size * GiB)
        if err:
            print(resp)  # Get rid of warning
            raise exception.VolumeBackendAPIException(data=err['messages'])

    def _extract_iscsi_uids(self, connector):
        if 'initiator' not in connector:
            if self.storage_protocol == 'iSCSI':
                msg = _('Host %s has no iSCSI initiator') % connector['host']
                LOG.error(msg)
                raise exception.VolumeBackendAPIException(data=msg)
            else:
                return ()
        return [connector['initiator']]

    def _extract_fc_uids(self, connector):
        if 'wwnns' not in connector or 'wwpns' not in connector:
            if self.storage_protocol == 'FC':
                msg = _('Host %s has no FC initiators') % connector['host']
                LOG.error(msg)
                raise exception.VolumeBackendAPIException(data=msg)
            else:
                return ()
        wwnns = connector['wwnns']
        wwpns = connector['wwpns']
        wwns = [(node + port).upper() for node, port in zip(wwnns, wwpns)]
        return map(lambda wwn: re.sub(r'\S\S',
                                      lambda m: m.group(0) + ':',
                                      wwn,
                                      len(wwn) / 2 - 1),
                   wwns)

    def _categorize_initiators(self, connector):
        if self.storage_protocol == 'iSCSI':
            initiator_uids = self._extract_iscsi_uids(connector)
        elif self.storage_protocol == 'FC':
            initiator_uids = self._extract_fc_uids(connector)
        else:
            initiator_uids = []
        registered_initiators = []
        orphan_initiators = []
        new_initiator_uids = []
        for initiator_uid in initiator_uids:
            initiator = self.client.get_initiator_by_uid(initiator_uid)
            if initiator:
                initiator = initiator[0]
                if 'parentHost' in initiator and initiator['parentHost']:
                    registered_initiators.append(initiator)
                else:
                    orphan_initiators.append(initiator)
            else:
                new_initiator_uids.append(initiator_uid)
        return registered_initiators, orphan_initiators, new_initiator_uids

    def _extract_host_id(self, registered_initiators, hostname=None):
        if registered_initiators:
            return registered_initiators[0]['parentHost']['id']
        if hostname:
            host = self.client.get_host_by_name(hostname, ('id',))
            if host:
                return host[0]['id']
        return None

    def _create_initiators(self, new_initiator_uids, host_id):
        for initiator_uid in new_initiator_uids:
            err, initiator = self.client.create_initiator(initiator_uid,
                                                          host_id)
            if err:
                print(initiator)  # Get rid of warning
                if err['httpStatusCode'] in (409,):
                    msg = _('Initiator %s had been created.') % initiator_uid
                    LOG.warn(msg)
                    return
                msg = _('Failed to create initiator %s') % initiator_uid
                LOG.error(msg)
                raise exception.VolumeBackendAPIException(data=msg)

    def _register_initiators(self, orphan_initiators, host_id):
        for initiator in orphan_initiators:
            err, resp = self.client.register_initiator(initiator['id'],
                                                       host_id)
            if err:
                print(resp)  # Get rid of warning
                msg = _('Failed to register initiator %(initiator)s '
                        'to %(host)s') %\
                    {'initiator': initiator['id'],
                     'host': host_id}
                LOG.error(msg)
                raise exception.VolumeBackendAPIException(data=msg)

    def _build_init_targ_map(self, mapping):
        """Function to process data from lookup service."""
        #   mapping
        #   {
        #        <San name>: {
        #            'initiator_port_wwn_list':
        #            ('200000051e55a100', '200000051e55a121'..)
        #            'target_port_wwn_list':
        #            ('100000051e55a100', '100000051e55a121'..)
        #        }
        #   }
        target_wwns = []
        init_targ_map = {}

        for san_name in mapping:
            mymap = mapping[san_name]
            for target in mymap['target_port_wwn_list']:
                if target not in target_wwns:
                    target_wwns.append(target)
            for initiator in mymap['initiator_port_wwn_list']:
                init_targ_map[initiator] = mymap['target_port_wwn_list']
        LOG.debug("target_wwns: %s", target_wwns)
        LOG.debug("init_targ_map: %s", init_targ_map)
        return target_wwns, init_targ_map

    def arrange_host(self, connector):
        registered_initiators, orphan_initiators, new_initiator_uids = \
            self._categorize_initiators(connector)
        host_id = self._extract_host_id(registered_initiators,
                                        connector['host'])
        if host_id is None:
            err, host = self.client.create_host(connector['host'])

            if err:
                print(host)  # Get rid of warning
                msg = _('Failed to create host %s.') % connector['host']
                LOG.error(msg)
                raise exception.VolumeBackendAPIException(data=msg)
            host_id = host['id']

        self._create_initiators(new_initiator_uids, host_id)
        self._register_initiators(orphan_initiators, host_id)
        return host_id

    def expose_lun(self, volume, host_id):
        lun_id = self._extra_lun_or_snap_id(volume)
        if self.lookup_service_instance and self.storage_protocol == 'FC':
            @lockutils.synchronized('emc-vnxe-host-' + host_id,
                                    "emc-vnxe-host-", True)
            def _expose_lun():
                return self.client.expose_lun(lun_id, host_id)

            err, resp = _expose_lun()
        else:
            err, resp = self.client.expose_lun(lun_id, host_id)
        if err:
            print(resp)  # Get rid of warning
            if err['errorCode'] in (0x6701020,):
                msg = _('LUN %(lun)s backing %(vol)s had been '
                        'exposed to %(host)s.') % \
                    {'lun': lun_id, 'vol': volume['name'],
                     'host': host_id}
                LOG.warn(msg)
                return
            msg = _('Failed to expose %(lun)s to %(host)s.') % \
                {'lun': lun_id, 'host': host_id}
            LOG.error(msg)
            raise exception.VolumeBackendAPIException(data=msg)

    def _get_driver_volume_type(self):
        if self.storage_protocol == 'iSCSI':
            return 'iscsi'
        elif self.storage_protocol == 'FC':
            return 'fibre_channel'
        else:
            return 'unknown'

    def _get_fc_zone_info(self, connector, targets):
        initiator_wwns = connector['wwpns']
        target_wwns = [item[1] for item in targets]
        mapping = self.lookup_service_instance.\
            get_device_mapping_from_network(initiator_wwns,
                                            target_wwns)
        target_wwns, init_targ_map = self._build_init_targ_map(mapping)
        return {'initiator_target_map': init_targ_map,
                'target_wwn': target_wwns}

    def get_connection_info(self, volume, connector, host_id):
        data = {'target_discovered': True,
                'target_lun': 'unknown',
                'volume_id': volume['id']}
        lun_id = self._extra_lun_or_snap_id(volume)

        lun = self.client.get_lun_by_id(lun_id, ('id', 'currentNode'))
        if not lun:
            msg = _('Connection information is unavaiable '
                    'because LUN %(lun)s backing %(vol)s had been deleted.')\
                % {'lun': lun_id, 'vol': volume['name']}
            LOG.error(msg)
            raise exception.VolumeBackendAPIException(data=msg)
        lun = lun[0]

        spa_targets = list(self.storage_targets['a'])
        spb_targets = list(self.storage_targets['b'])
        random.shuffle(spa_targets)
        random.shuffle(spb_targets)
        # Owner SP is preferred
        if lun['currentNode'] == 0:
            targets = spa_targets + spb_targets
        else:
            targets = spb_targets + spa_targets

        if not targets:
            msg = _('Connection information is unavailable '
                    'because no target ports are available in the system.')
            LOG.error(msg)
            raise exception.VolumeBackendAPIException(data=msg)
        if self.storage_protocol == 'iSCSI':
            data['target_iqn'] = targets[0][0]
            data['target_portal'] = '%s:3260' % targets[0][1]
        elif self.storage_protocol == 'FC':
            host = self.client.get_host_by_id(host_id,
                                              ('fcHostInitiators',))
            if not host or not host[0]['fcHostInitiators']:
                msg = _('Connection information is unavailable because '
                        'no FC initiator can access resources in %s') % \
                    host_id
                LOG.error(msg)
                raise exception.VolumeBackendAPIException(data=msg)
            host = host[0]
            logined_fc_set = set()
            for initiator in host['fcHostInitiators']:
                paths = self.client.get_initiator_paths_by_initiator_id(
                    initiator['id'], ('fcPort', 'isLoggedIn'))
                for path in paths:
                    if path['isLoggedIn']:
                        logined_fc_set.add(path['fcPort']['id'])
            if self.lookup_service_instance:
                zone_info = self._get_fc_zone_info(connector, targets)
                data.update(zone_info)
            else:
                accessible_targets = filter(lambda entry:
                                            entry[2] in logined_fc_set,
                                            targets)
                if not accessible_targets:
                    msg = _('Connection information is unavailable '
                            'because no FC initiator in %s has paths '
                            'to the system.') % host_id
                    LOG.error(msg)
                    raise exception.VolumeBackendAPIException(data=msg)
                data['target_wwn'] = map(lambda entry: entry[1],
                                         accessible_targets)
            LOG.debug('FC Target WWNs accessible to %(host)s: %(targets)s.'
                      % {'host': connector['host'],
                         'targets': data['target_wwn']})

        host_lun = self.client.get_host_lun_by_ends(host_id, lun_id,
                                                    fields=('hlu',))
        if not host_lun:
            pass
        data['target_lun'] = host_lun[0]['hlu']

        access_mode = None
        if volume.get('volume_admin_metadata'):
            volume_metadata = {}
            for metadata in volume['volume_admin_metadata']:
                volume_metadata[metadata['key']] = metadata['value']
            access_mode = volume_metadata.get('attached_mode')
            if access_mode is None:
                access_mode = ('ro'
                               if volume_metadata.get('readonly') == 'True'
                               else 'rw')
        else:
            access_mode = 'rw'

        LOG.debug('Volume %(vol)s Access mode is: %(access)s.'
                  % {'vol': volume['name'],
                     'access': access_mode})
        data['access_mode'] = access_mode

        connection_info = {
            'driver_volume_type': self._get_driver_volume_type(),
            'data': data}
        return json.dumps(connection_info)

    def initialize_connection(self, volume, connector):
        flow_name = 'initialize_connection'
        volume_flow = linear_flow.Flow(flow_name)
        volume_flow.add(ArrangeHostTask(self, connector),
                        ExposeLUNTask(self, volume),
                        GetConnectionInfoTask(self, volume, connector))

        flow_engine = taskflow.engines.load(volume_flow,
                                            store={})
        flow_engine.run()
        return json.loads(flow_engine.storage.fetch('connection_info'))

    def hide_lun(self, volume, host_id):
        lun_id = self._extra_lun_or_snap_id(volume)
        lun = self.client.get_lun_by_id(lun_id, ('id',))
        if not lun:
            msg = _("LUN %(lun)s backing %(vol)s had been deleted.") % \
                {'lun': lun_id, 'vol': volume['name']}
            LOG.warn(msg)
            return
        err, resp = self.client.hide_lun(lun_id, host_id)
        if err:
            print(resp)  # Get rid of warning
            if err['errorCode'] in (0x6701020,):
                msg = _('LUN %(lun)s backing %(vol) had been '
                        'hidden from %(host)s.') % \
                    {'lun': lun_id, 'vol': volume['name'],
                     'host': host_id}
                LOG.warn(msg)
                return
            msg = _('Failed to hide %(vol)s from %(host)s.') % \
                {'vol': volume['name'], 'host': host_id}
            raise exception.VolumeBackendAPIException(data=err['messages'])

    def get_fc_zone_info_for_empty_host(self, connector, host_id):
        @lockutils.synchronized('emc-vnxe-host-' + host_id,
                                "emc-vnxe-host-", True)
        def _get_fc_zone_info_in_sync():
            if self.isHostContainsLUNs(host_id):
                return {}
            else:
                targets = self.storage_targets['a'] + self.storage_targets['b']
                return self._get_fc_zone_info(connector,
                                              targets)
        return {
            'driver_volume_type': self._get_driver_volume_type(),
            'data': _get_fc_zone_info_in_sync()}

    def terminate_connection(self, volume, connector, **kwargs):

        registered_initiators, orphan_initiators, new_initiator_uids = \
            self._categorize_initiators(connector)
        host_id = self._extract_host_id(registered_initiators,
                                        connector['host'])
        if not host_id:
            print(orphan_initiators, new_initiator_uids)  # Get rid of warning
            msg = _("Host using %s is not found.") % volume['name']
            LOG.warn(msg)
        else:
            self.hide_lun(volume, host_id)

        if self.lookup_service_instance and self.storage_protocol == 'FC':
            return self.get_fc_zone_info_for_empty_host(connector, host_id)
        else:
            return

    def isHostContainsLUNs(self, host_id):
        host = self.client.get_host_by_id(host_id, ('hostLUNs',))
        if not host:
            return False
        else:
            luns = host[0]['hostLUNs']
            return True if luns else False

    def get_volume_stats(self, refresh=False):
        if refresh:
            self.update_volume_stats()
        return self.stats

    def update_volume_stats(self):
        LOG.debug("Updating volume stats")
        data = {}
        backend_name = self.configuration.safe_get('volume_backend_name')
        data['volume_backend_name'] = backend_name or 'EMCVNXeDriver'
        data['storage_protocol'] = self.storage_protocol
        data['driver_version'] = VERSION
        data['reserved_percentage'] = 0
        data['vendor_name'] = "EMC"
        pool = self.client.get_pool_by_id(self.pool_id,
                                          ('sizeTotal', 'sizeFree'))
        if pool:
            pool = pool[0]
            data['free_capacity_gb'] = pool['sizeFree'] / GiB
            data['total_capacity_gb'] = pool['sizeTotal'] / GiB
        else:
            data['free_capacity_gb'] = 'unknown'
            data['total_capacity_gb'] = 'unknown'
            msg = _('Failed to get information on %s.') % self.pool_id
            LOG.error(msg)
        self.stats = data
        LOG.debug('Volume Stats: %s', data)
        return self.stats

    def manage_existing_get_size(self, volume, ref):
        """Return size of volume to be managed by manage_existing.
        """
        # Check that the reference is valid
        if 'id' not in ref:
            reason = _('Reference must contain lun_id element.')
            raise exception.VolumeBackendAPIException(
                data=reason)

        # Check for existence of the lun
        lun = self.client.get_lun_by_id(ref['id'])
        if len(lun) == 0:
            reason = _('Find no lun with the specified lun_id %s.') % ref['id']
            raise exception.VolumeBackendAPIException(
                data=reason)

        if lun[0]['pool']['id'] != self.pool_id:
            reason = _('The input lun %s is not in a manageable '
                       'pool backend') % ref['id']
            raise exception.VolumeBackendAPIException(
                data=reason)
        return lun[0]['sizeTotal'] / GiB

    def manage_existing(self, volume, ref):
        """Manage an existing lun in the array.
        """
        self.client.modify_lun_name(ref['id'], volume['name'])

        pl_dict = {'system': self.storage_serial_number,
                   'type': 'lun',
                   'id': ref['id']}
        model_update = {'provider_location':
                        self._dumps_provider_location(pl_dict)}
        volume['provider_location'] = model_update['provider_location']
        return model_update


class EMCVNXeDriver(san.SanDriver):
    """EMC VMXe Driver."""

    def __init__(self, *args, **kwargs):

        super(EMCVNXeDriver, self).__init__(*args, **kwargs)
        self.helper = EMCUnityHelper(self.configuration)

    def check_for_setup_error(self):
        pass

    def create_volume(self, volume):
        return self.helper.create_volume(volume)

    def create_volume_from_snapshot(self, volume, snapshot):
        return self.helper.create_volume_from_snapshot(volume, snapshot)

    def create_cloned_volume(self, volume, src_vref):
        return self.helper.create_cloned_volume(volume, src_vref)

    def delete_volume(self, volume):
        return self.helper.delete_volume(volume)

    def create_snapshot(self, snapshot):
        """Creates a snapshot."""
        LOG.debug('Entering create_snapshot.')
        snapshotname = snapshot['name']
        volumename = snapshot['volume_name']
        snap_desc = snapshot['display_description']

        LOG.info(_('Create snapshot: %(snapshot)s: volume: %(volume)s')
                 % {'snapshot': snapshotname,
                    'volume': volumename})

        return self.helper.create_snapshot(
            snapshot, snapshotname, snap_desc)

    def delete_snapshot(self, snapshot):
        """Delete a snapshot."""
        LOG.info(_('Delete snapshot: %s') % snapshot['name'])
        return self.helper.delete_snapshot(snapshot)

    def ensure_export(self, context, volume):
        pass

    def create_export(self, context, volume):
        pass

    def remove_export(self, context, volume):
        pass

    def check_for_export(self, context, volume_id):
        pass

    def extend_volume(self, volume, new_size):
        return self.helper.extend_volume(volume, new_size)

    @AddFCZone
    def initialize_connection(self, volume, connector):
        return self.helper.initialize_connection(volume, connector)

    @RemoveFCZone
    def terminate_connection(self, volume, connector, **kwargs):
        return self.helper.terminate_connection(volume, connector)

    def get_volume_stats(self, refresh=False):
        return self.helper.get_volume_stats(refresh)

    def update_volume_stats(self):
        return self.helper.update_volume_stats()

    def manage_existing_get_size(self, volume, existing_ref):
        """Return size of volume to be managed by manage_existing.
        """
        return self.helper.manage_existing_get_size(
            volume, existing_ref)

    def manage_existing(self, volume, existing_ref):
        LOG.debug("Reference lun id %s." % existing_ref['id'])
        return self.helper.manage_existing(
            volume, existing_ref)
