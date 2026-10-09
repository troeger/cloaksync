# Active Directory

Active Directory (AD) is Microsoft’s directory service. Active Directory is the backbone of identity and access management for Windows-based networks. It is a central database of the people and things in an organisation.

As of multiple industry estimates, over 90% of Fortune 1000 companies and the vast majority of medium to large enterprises globally use Microsoft AD to manage identity and access within their networks.

Note: active directory is not necessarily related to the cloaksync project. Our running Keycloak instance happens to get its user data from there. Where user data is coming from is not relevant to this project (as long as its stored in keycloak).

## Directory Service

Directory services play an important role in developing intranet and Internet applications by allowing the sharing of information about users, systems, networks, services, and applications throughout the network.

A directory service is a database built for a specific access pattern:

- It has many reads and few writes.
- The data is a hierarchical tree of entries.
- Every entry is an object with typed attributes.
- The schema defines which attributes each type may have.

The idea is that clients can search it quickly, for example “all users in group X whose department is IT”.

## Key Components

- Domain Controller: The AD server. It holds a copy of the directory and answers requests.
- Directory database: The tree of objects (users, groups, computers) with their attributes.
- LDAP service: The interface for reading and searching the directory.

There are other important components, but we dont need to dive into them deeply here. For this project, its good to know that student data is saved in Active Directory. Keycloak accesses it through the LDAP interface.

## LDAP

The active directory database can be queried thorugh the Lightweight Directory Access Protocol (LDAP) protocoll. LDAP is an Internet protocol for accessing directory information services.

A common use of LDAP is to provide a central place to store usernames and passwords. This allows many different applications and services to connect to the LDAP server to validate users.

# Sources

<https://en.wikipedia.org/wiki/Active_Directory>
<https://medium.com/@abdurraafay/what-is-active-directory-its-architecture-components-and-importance-1de3d982c9fc>
<https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol>
