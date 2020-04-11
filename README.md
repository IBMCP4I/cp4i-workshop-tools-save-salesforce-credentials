# Save Salesforce credentials as OpenShift secret

This is a  *Node.js* app that is used in the Cloud Pak for Integration workshop to make it easier to store Salesforce credentials as an OpenShift  secret  in the format require by an App Connect Integration Server. It uses the same LDAP used for students in the Cloud Pak for Integration workshop and then names the secret `username-sf-connect` where `username` is the student's LDAP username.

## Obtaining an OpenShift token
In order for the app to create a secret via the  OpenShift Kubernetes API, the URL of the API endpoint and a token  is required (see next sections)

The token should be generated by a service account with enough permissions to create a secret in the namespace where the App Connect dashboard component of CP4I is installed.

The following commands (run by a user with appropriate privileges) will create a service account named `foobar` in the `ace` namespace with enough permissions to create secrets:

```
oc create sa foobar -n ace
oc policy add-role-to-user admin system:serviceaccount:ace:foobar
```

The following command will return the token from a service account named `foobar` needed to authenticate against the OpenShift API.

```
oc sa get-token foobar
```

## Running on Cloud Foundry
The run this app on Cloud Foundry rename the file `manifest.sample.yml` to `manifest.yml` and set the correct  values for the following ENV vars defined in the manifest file
```
---
applications:
 - name: save-sf-creds
   path: .
   instances: 1
   memory: 256MB
   routes:
   - route: save-sf-creds.us-south.cf.appdomain.cloud
   env:
    OPENSHIFT_API_BASE: [OpenShift API base URL of CP4I cluster]
    OPENSHIFT_TOKEN: [token of a service account that has sufficient permissions to create a secret in the ace project]
    LDAP_URL: [ LDAP url eg ldap://nnn.nnn.nnn.nnn:389]
    LDAP_BIND_DN: [LDAP Bind DN]
    LDAP_BIND_CREDENTIALS: [LDAP Bind DN password]
    LDAP_SEARCH_BASE: [LDAP user search base eg ou=users,dc=cda-ocp,dc=cloud]
    LDAP_SEARCH_FILTER: [LDSP search filter eg (uid={{username}})]
```

## Running locally
Define the ENV vars in a file called `.env`. Rename the file `.env.sample` to `.env` and adjust the values appropriately.

Run the following commands from  the root folder of this repo to install the  requirements:

```
npm install
```

Run the following commands from  the root folder of this repo to start the app

```
node bin/www
```

Access the app at http://localhost:3000
