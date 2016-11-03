Inspec Profile for STIGs
=====================
[![Build Status](https://travis-ci.org/inspec-stigs/inspec-stig-apache.svg?branch=master)](https://travis-ci.org/inspec-stigs/inspec-stig-apache)

Based on STIGs found at: http://iase.disa.mil/stigs

## Usage ##
### Chef Compliance ###
The intended usage of this profile would be to be uploaded to Chef Compliance.

1. Clone this repository
2. Zip the entire directory `zip -r apache_stig.zip inspec-stig-apache`
3. Log into the WebUI > Click **Compliance** from the side menu > Click **Add Profile**
4. Choose your **apache_stig.zip** from your local workstation.

### Locally ###

```inspec exec path/to/controls/profiles.rb -t ssh://user@ip --password 'password' --sudo```

Futher testing examples:
* [Profile Testing][]

## Resources ##
* [Inspec Resources][]
* [Profile Testing][]
* [DISA Apache STIG][]
* [Profile Generation][]


[Inspec Resources]: http://inspec.io/docs/reference/resources/
[Profile Testing]: http://www.anniehedgie.com/inspec-basics-6
[DISA Apache STIG]: http://iase.disa.mil/stigs/app-security/web-servers/Pages/index.aspx
[Profile Generation]: https://github.com/inspec-stigs/inspec-stigs/blob/master/read_stig_json.rb
