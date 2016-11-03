# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13613 - The Web site software used with the web server must have all applicable security patches applied and documented.'
control 'V-13613' do
  impact 0.5
  title 'The Web site software used with the web server must have all applicable security patches applied and documented.'
  desc 'The IAVM process does not address all patches that have been identified for the host operating system or, in this case, the web server software environment. Many vendors have subscription services available to notify users of known security threats. The site needs to be aware of these fixes and make determinations based on local policy and what software features are installed, if these patches need to be applied.   In some cases, patches also apply to middleware and database systems. Maintaining the security of web servers requires frequent reviews of security notices. Many security notices mandate the installation of a software patch to overcome security vulnerabilities.   SAs and ISSOs should regularly check the vendor support web site for patches and information related to the web server software. All applicable security patches will be applied to the operating system and to the web server software. Security patches are deemed applicable if the product is installed, even if it is not used or is disabled.  '
  tag 'stig', 'V-13613'
  tag severity: 'medium'
  tag checkid: 'C-33653r2_chk'
  tag fixid: 'F-29289r1_fix'
  tag version: 'WA230 A22'
  tag ruleid: 'SV-32969r2_rule'
  tag fixtext: 'Establish a detailed process as part of the configuration management plan to stay compliant with all web server security-related patches.'
  tag checktext: 'Query the web administrator to determine if the site has a detailed process as part of its configuration management plan to stay compliant with all security-related patches.

Proposed Questions:
How does the SA stay current with web server vendor patches?
How is the SA notified when a new security patch is issued by the vendor? (Exclude the IAVM.)
What is the process followed for applying patches to the web server?

If the site is not in compliance with all applicable security patches, this is a finding.'

# START_DESCRIBE V-13613
# No Check possible
# STOP_DESCRIBE V-13613

end

