# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-2234 - Public web server resources must not be shared with private assets.'
control 'V-2234' do
  impact 0.5
  title 'Public web server resources must not be shared with private assets.'
  desc 'It is important to segregate public web server resources from private resources located behind the DoD DMZ in order to protect private assets. When folders, drives or other resources are directly shared between the public web server and private servers the intent of data and resource segregation can be compromised.   In addition to the requirements of the DoD Internet-NIPRNet DMZ STIG that isolates inbound traffic from the external network to the internal network, resources such as printers, files, and folders/directories will not be shared between public web servers and assets located within the internal network.   '
  tag 'stig', 'V-2234'
  tag severity: 'medium'
  tag checkid: 'C-33639r1_chk'
  tag fixid: 'F-29280r1_fix'
  tag version: 'WG040 A22'
  tag ruleid: 'SV-32957r1_rule'
  tag fixtext: 'Configure the public web server to not have a trusted relationship with any system resource that is also not accessible to the public. Web content is not to be shared via Microsoft shares or NFS mounts.'
  tag checktext: 'Determine whether the public web server has a two-way trusted relationship with any private asset located within the network. Private web server resources (e.g., drives, folders, printers, etc.) will not be directly mapped to or shared with public web servers.

If sharing is selected for any web folder, this is a finding.

The following checks indicate inappropriate sharing of private resources with the public web server:

If private resources (e.g., drives, partitions, folders/directories, printers, etc.) are shared with the public web server, then this is a finding.
'

# START_DESCRIBE V-2234
  doc_root =  command("grep ^DocumentRoot /etc/httpd/conf/httpd.conf | awk -F '\"' '{print $2}'").stdout.chomp
  describe mount(doc_root) do
    its('type') { should_not eq  'nfs' }
  end
# STOP_DESCRIBE V-2234

end

