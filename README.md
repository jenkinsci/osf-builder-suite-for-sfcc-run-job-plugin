# OSF Builder Suite For Salesforce Commerce Cloud :: Run Job
Import your site data to a Salesforce Commerce Cloud instance

**OSF Builder Suite For Salesforce Commerce Cloud :: Run Job** is a very easy-to-use and highly configurable Jenkins plugin that is used to run your Salesforce Commerce Cloud jobs on your continuous integration sandbox, development or staging instance.

If you have a bug to report or maybe a feature that you wish to request, please do so [on GitHub, on the project's issues page](https://github.com/jenkinsci/osf-builder-suite-for-sfcc-run-job-plugin/issues).

 
# Features

- Simple. It does one thing, and it does it well.
- Easy to install, use and keep updated.
- Easy to configure. The plugin can be configured from the Jenkins web interface.
- Support for classical mode, Jenkins [Pipelines](https://jenkins.io/doc/book/pipeline/) and also the new modern [Blue Ocean](https://jenkins.io/doc/book/blueocean/) interface.
- Super flexible. Every little thing is configurable so that the plugin can be easily adjusted to your workflow.
- Integrated with the Jenkins [credentials plugin](https://plugins.jenkins.io/credentials) so that your credentials are safely stored encrypted.
- Good documentation. Every option is documented both here on this page but also inline in Jenkins's UI by clicking the question mark icon next to the item for which you wish to display the help information.
- Support for HTTP proxy with basic or [NTLM](https://en.wikipedia.org/wiki/NT_LAN_Manager) authentication.
- Free
- Open source

 
# Installation

Just go to `Manage Jenkins > Manage Plugins > Available`, search for `OSF Builder Suite`, select `OSF Builder Suite For Salesforce Commerce Cloud :: Run Job` and click `Download now and install after restart` button.

 
# Configuration

![](imgs/hostname.png)

Hostname of the SFCC instance where this build should be deployed. Examples:

|                                              |                                                                                   |
| -------------------------------------------: | :-------------------------------------------------------------------------------- |
|      `staging-realm-customer.demandware.net` | For deployments to a staging instance that does not have two factor auth enabled. |
|  `development-realm-customer.demandware.net` | For deployments to a development instance.                                        |
|        `devNN-realm-customer.demandware.net` | For deployments to a sandbox instance.                                            |


![](imgs/oc_credentials.png)

Open Commerce API credentials of type `OSF Builder Suite :: Open Commerce API Credentials` for the SFCC instance where this build should be deployed.

![](imgs/oc_version.png)

The version to be used by the calls made to OCAPI. The Open Commerce API Version starts with the character `v` (lowercase) followed by the actual version number, separated by an underscore.

For example: `v19_10`
 
![](imgs/proxy_host.png)

If your Jenkins server sits behind a firewall and does not have direct access to the internet, you can specify the HTTP proxy host in this field to allow Jenkins to connect to the internet trough it.

![](imgs/proxy_port.png)

This field works in conjunction with the proxy host field to specify the HTTP proxy port.

![](imgs/proxy_username.png)

This field works in conjunction with the proxy host field to specify the username used to authenticate with the proxy.

If this proxy requires Microsoft's [NTLM](https://en.wikipedia.org/wiki/NT_LAN_Manager) authentication scheme then the domain name can be encoded within the username by prefixing the domain name followed by a back-slash `\` before the username, e.g `ACME\John Doe`.

![](imgs/proxy_password.png)

This field works in conjunction with the proxy host field to specify the HTTP proxy password.

![](imgs/ssl_validation.png)

When this option is checked, the builder will no longer validate the SSL certificate and hostname of the target instance.

**This has potential security implications so make sure you know what you are doing before enabling this option!**

# **Open Commerce API Settings**
Go to `Administration > Site Development > Open Commerce API Settings`, select type `Data`, select context `Global` and add following configuration:

```JSON
{
    "_v": "19.10",
    "clients": [
        {
            "client_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "resources": [
                {
                    "resource_id": "/jobs/*/executions",
                    "methods": ["post"],
                    "read_attributes": "(**)",
                    "write_attributes": "(**)"
                },
                {
                    "resource_id": "/jobs/*/executions/*",
                    "methods": ["get"],
                    "read_attributes": "(**)",
                    "write_attributes": "(**)"
                }
            ]
        }
    ]
}
```

# Jenkins Pipeline Configuration
Here's a sample pipeline configuration to get you started:

```Groovy
node {
    stage('RunJob') {
        osfBuilderSuiteForSFCCRunJob(
            hostname: '???',
            ocCredentialsId: '???',
            ocVersion: 'v19_10',
            jobName: 'Reindex',
            jobArguments: [
                [name: 'name', value: 'value']
            ]
        )
    }
}
```

You can also always consult the pipelines documentation available at <https://jenkins.io/doc/book/pipeline/> or check the pipeline syntax link right inside Jenkins on the left navigation menu.

![](imgs/left_nav.png)
 
# Version history
<https://github.com/jenkinsci/osf-builder-suite-for-sfcc-run-job-plugin/releases>


# Dev
- `mvn hpi:run`
- `mvn clean package hpi:hpi`
- `mvn release:prepare release:perform`
