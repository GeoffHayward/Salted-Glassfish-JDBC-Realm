glassfish-jdbc-realm-ehanced
============================
A working salted glassfish/payara realm.

The original work for this realm was by Markus Eisele. Here is the related blog-post 
http://blog.eisele.net/2012/07/glassfish-jdbc-security-with-salted.html that is relating to the original work.

==========================

Build it as a jar. Copy the {GLASSFISH_HOME}/domain/lib. Then add the folowing to your database:
<pre>
USE jdbcrealmdb;
CREATE TABLE `users` (
`username` varchar(255) NOT NULL,
`salt` varchar(255) NOT NULL,
`password` varchar(255) DEFAULT NULL,
PRIMARY KEY (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
</pre>

<pre>
CREATE TABLE `groups` (
`username` varchar(255) DEFAULT NULL,
`groupname` varchar(255) DEFAULT NULL)
ENGINE=InnoDB DEFAULT CHARSET=utf8; 
CREATE INDEX groups_users_FK1 ON groups(username ASC);
</pre>
The optional propeties are:
* "jaas-context" the name of the realm
* "dataSource" the jdbc connection name

The login.conf file needs:
<pre>
userRealm {
	org.geoffhayward.security.LoginModule required;
};
</pre>
