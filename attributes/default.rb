# encoding: utf-8
# Author:: Joshua Timberman <joshua@getchef.com>
# Copyright:: Copyright 2009-2014, Chef Software, Inc.
# Author:: John Ko <git@johnko.ca>
# Copyright:: Copyright 2014, John Ko
#
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Generic cookbook attributes
default['postfix']['mail_type']  = 'client'
default['postfix']['relayhost_role'] = 'relayhost'
default['postfix']['multi_environment_relay'] = false
default['postfix']['use_procmail'] = false
default['postfix']['transports'] = {}
default['postfix']['access'] = {}
default['postfix']['virtual_aliases'] = {}
default['postfix']['main_template_source'] = 'postfix'
default['postfix']['master_template_source'] = 'postfix'
default['postfix']['sender_canonical_map_entries'] = {}
default['postfix']['smtp_generic_map_entries'] = {}

case node['platform']
when 'smartos'
  default['postfix']['conf_dir'] = '/opt/local/etc/postfix'
  default['postfix']['aliases_db'] = '/opt/local/etc/postfix/aliases'
  default['postfix']['transport_db'] = '/opt/local/etc/postfix/transport'
  default['postfix']['access_db'] = '/opt/local/etc/postfix/access'
  default['postfix']['virtual_alias_db'] = '/opt/local/etc/postfix/virtual'
when 'freebsd'
  default['postfix']['conf_dir'] = '/usr/local/etc/postfix'
  default['postfix']['aliases_db'] = '/etc/aliases'
  default['postfix']['transport_db'] = '/usr/local/etc/postfix/transport'
when 'omnios'
  default['postfix']['conf_dir'] = '/opt/omni/etc/postfix'
  default['postfix']['aliases_db'] = 'opt/omni/etc/postfix/aliases'
  default['postfix']['transport_db'] = '/opt/omni/etc/postfix/transport'
  default['postfix']['access_db'] = '/opt/omni/etc/postfix/access'
  default['postfix']['virtual_alias_db'] = '/etc/omni/etc/postfix/virtual'
  default['postfix']['uid'] = 11
else
  default['postfix']['conf_dir'] = '/etc/postfix'
  default['postfix']['aliases_db'] = '/etc/aliases'
  default['postfix']['transport_db'] = '/etc/postfix/transport'
  default['postfix']['access_db'] = '/etc/postfix/access'
  default['postfix']['virtual_alias_db'] = '/etc/postfix/virtual'
end

# Non-default main.cf attributes
default['postfix']['main']['biff'] = 'no'
default['postfix']['main']['append_dot_mydomain'] = 'no'
default['postfix']['main']['myhostname'] = (node['fqdn'] || node['hostname']).to_s.chomp('.')
default['postfix']['main']['mydomain'] = (node['domain'] || node['hostname']).to_s.chomp('.')
default['postfix']['main']['myorigin'] = '$myhostname'
default['postfix']['main']['mydestination'] = [node['postfix']['main']['myhostname'], node['hostname'], 'localhost.localdomain', 'localhost'].compact
default['postfix']['main']['smtpd_use_tls'] = 'yes'
default['postfix']['main']['smtp_use_tls'] = 'yes'
default['postfix']['main']['smtp_sasl_auth_enable'] = 'no'
default['postfix']['main']['use_alias_maps'] = 'no'
default['postfix']['main']['use_transport_maps'] = 'no'
default['postfix']['main']['use_access_maps'] = 'no'
default['postfix']['main']['use_virtual_aliases'] = 'no'
default['postfix']['main']['mailbox_size_limit'] = 0
default['postfix']['main']['mynetworks'] = nil
default['postfix']['main']['inet_interfaces'] = 'loopback-only'

# Conditional attributes
case node['platform_family']
when 'smartos'
  default['postfix']['main']['smtpd_use_tls'] = 'no'
  default['postfix']['main']['smtp_use_tls'] = 'no'
  cafile = '/opt/local/etc/postfix/cacert.pem'
when 'rhel'
  cafile = '/etc/pki/tls/cert.pem'
when 'freebsd'
  # start defaults in 2.11.1_2,1 on freebsd:10:x86:64
    default['postfix']['main']['queue_directory'] = '/var/spool/postfix'
    default['postfix']['main']['command_directory'] = '/usr/local/sbin'
    default['postfix']['main']['daemon_directory'] = '/usr/local/libexec/postfix'
    default['postfix']['main']['data_directory'] = '/var/db/postfix'
    default['postfix']['main']['mail_owner'] = 'postfix'
    default['postfix']['main']['unknown_local_recipient_reject_code'] = '550'
    default['postfix']['main']['mynetworks_style'] = 'host'
    default['postfix']['main']['debug_peer_level'] = '2'
    default['postfix']['main']['debugger_command'] = 'PATH=/bin:/usr/bin:/usr/local/bin:/usr/X11R6/bin ddd $daemon_directory/$process_name $process_id & sleep 5'
    default['postfix']['main']['sendmail_path'] = '/usr/local/sbin/sendmail'
    default['postfix']['main']['newaliases_path'] = '/usr/local/bin/newaliases'
    default['postfix']['main']['mailq_path'] = '/usr/local/bin/mailq'
    default['postfix']['main']['setgid_group'] = 'maildrop'
    default['postfix']['main']['html_directory'] = '/usr/local/share/doc/postfix'
    default['postfix']['main']['manpage_directory'] = '/usr/local/man'
    default['postfix']['main']['sample_directory'] = '/usr/local/etc/postfix'
    default['postfix']['main']['readme_directory'] = '/usr/local/share/doc/postfix'
    default['postfix']['main']['inet_protocols'] = 'ipv4'
  # end defaults in 2.11.1_2,1 on freebsd:10:x86:64
else
  cafile = "#{node['postfix']['conf_dir']}/cacert.pem"
end

if node['postfix']['use_procmail']
  default['postfix']['main']['mailbox_command'] = '/usr/bin/procmail -a "$EXTENSION"'
end

if node['postfix']['main']['smtpd_use_tls'] == 'yes'
  default['postfix']['main']['smtpd_tls_cert_file'] = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
  default['postfix']['main']['smtpd_tls_key_file'] = '/etc/ssl/private/ssl-cert-snakeoil.key'
  default['postfix']['main']['smtpd_tls_CAfile'] = cafile
  default['postfix']['main']['smtpd_tls_session_cache_database'] = 'btree:${data_directory}/smtpd_scache'
end

if node['postfix']['main']['smtp_use_tls'] == 'yes'
  default['postfix']['main']['smtp_tls_CAfile'] = cafile
  default['postfix']['main']['smtp_tls_session_cache_database'] = 'btree:${data_directory}/smtp_scache'
end

if node['postfix']['main']['smtp_sasl_auth_enable'] == 'yes'
  default['postfix']['sasl_password_file'] = "#{node['postfix']['conf_dir']}/sasl_passwd"
  default['postfix']['main']['smtp_sasl_password_maps'] = "hash:#{node['postfix']['sasl_password_file']}"
  default['postfix']['main']['smtp_sasl_security_options'] = 'noanonymous'
  default['postfix']['sasl']['smtp_sasl_user_name'] = ''
  default['postfix']['sasl']['smtp_sasl_passwd']    = ''
  default['postfix']['main']['relayhost'] = ''
end

if node['postfix']['main']['use_alias_maps'] == 'yes'
   default['postfix']['main']['alias_maps'] = ["hash:#{node['postfix']['aliases_db']}"]
end

if node['postfix']['main']['use_transport_maps'] == 'yes'
   default['postfix']['main']['transport_maps'] = ["hash:#{node['postfix']['transport_db']}"]
end

if node['postfix']['main']['use_access_maps'] == 'yes'
   default['postfix']['main']['access_maps'] = ["hash:#{node['postfix']['access_db']}"]
end

if node['postfix']['main']['use_virtual_aliases'] == 'yes'
  default['postfix']['main']['virtual_alias_maps'] = ["hash:#{node['postfix']['virtual_alias_db']}"]
end

# # Default main.cf attributes according to `postconf -d`
# default['postfix']['main']['relayhost'] = ''
# default['postfix']['main']['milter_default_action']  = 'tempfail'
# default['postfix']['main']['milter_protocol']  = '6'
# default['postfix']['main']['smtpd_milters']  = ''
# default['postfix']['main']['non_smtpd_milters']  = ''
# default['postfix']['main']['sender_canonical_classes'] = nil
# default['postfix']['main']['recipient_canonical_classes'] = nil
# default['postfix']['main']['canonical_classes'] = nil
# default['postfix']['main']['sender_canonical_maps'] = nil
# default['postfix']['main']['recipient_canonical_maps'] = nil
# default['postfix']['main']['canonical_maps'] = nil

# Master.cf attributes
default['postfix']['master']['submission'] = false


# OS Aliases
case node['platform']
when 'freebsd'
  default['postfix']['aliases'] = {
    'MAILER-DAEMON'  =>  'postmaster',
   #'postmaster'     =>  'root', # defined in file
    '_dhcp'          =>  'root',
    '_pflogd'        =>  'root',
    'auditdistd'     =>  'root',
    'bin'            =>  'root',
    'bind'           =>  'root',
    'daemon'         =>  'root',
    'games'          =>  'root',
    'hast'           =>  'root',
    'kmem'           =>  'root',
    'mailnull'       =>  'postmaster',
    'man'            =>  'root',
    'news'           =>  'root',
    'nobody'         =>  'root',
    'operator'       =>  'root',
    'pop'            =>  'root',
    'proxy'          =>  'root',
    'smmsp'          =>  'postmaster',
    'sshd'           =>  'root',
    'system'         =>  'root',
    'toor'           =>  'root',
    'tty'            =>  'root',
    'usenet'         =>  'news',
    'uucp'           =>  'root',
    'abuse'          =>  'postmaster',
    'security'       =>  'root',
    'ftp'            =>  'root',
    'ftp-bugs'       =>  'ftp',
    'named'          =>  'root',
    'www'            =>  'root',
    'postfix'        =>  'root',
    'manager'        =>  'root',
    'dumper'         =>  'root'
  }
else
  default['postfix']['aliases'] = {}
end

# if freebsd jail, use interface ip
case node['platform']
when 'freebsd'
  if node[:virtualization][:system] == "jail"
    if node[:virtualization][:role] == "guest"
      set['postfix']['main']['inet_interfaces'] = node['ipaddress']
    end
  end
end

# root group
default['postfix']['rootgroup']    = case node['platform_family']
                                     when 'freebsd'
                                       'wheel'
                                     else
                                       'root'
                                     end
