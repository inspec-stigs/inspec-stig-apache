# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-2236 - Installation of a compiler on production web server is prohibited.'
control 'V-2236' do
  impact 0.5
  title 'Installation of a compiler on production web server is prohibited.'
  desc 'The presence of a compiler on a production server facilitates the malicious user’s task of creating custom versions of programs and installing Trojan Horses or viruses. For example, the attacker’s code can be uploaded and compiled on the server under attack.'
  tag 'stig', 'V-2236'
  tag severity: 'medium'
  tag checkid: 'C-33638r4_chk'
  tag fixid: 'F-29279r4_fix'
  tag version: 'WG080 A22'
  tag ruleid: 'SV-32956r3_rule'
  tag fixtext: 'Remove any compiler found on the production web server, but if the compiler program is needed to patch or upgrade an application suite in a production environment or the compiler is embedded and will break the suite if removed, document the compiler installation with the ISSO/ISSM and ensure that the compiler is restricted to only administrative users.'
  tag checktext: 'Query the SA and the Web Manager to determine if a compiler is present on the server.  If a compiler is present, this is a finding. 

NOTE:  If the web server is part of an application suite and a compiler is needed for installation, patching, and upgrading of the suite or if the compiler is embedded and cant be removed without breaking the suite, document the installation of the compiler with the ISSO/ISSM and verify that the compiler is restricted to administrative users only.  If documented and restricted to administrative users, this is not a finding.
'

# START_DESCRIBE V-2236
# No Check possible
# STOP_DESCRIBE V-2236

end

